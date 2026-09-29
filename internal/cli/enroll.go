package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/instances"
	"dynamicflow/internal/release"
	"dynamicflow/internal/serving"
	"dynamicflow/internal/signing"
	"dynamicflow/internal/sshkeys"
)

type localEnrollment struct {
	Schema          int                           `json:"schema"`
	Name            string                        `json:"name"`
	Profile         string                        `json:"profile"`
	KeyScope        sshkeys.Scope                 `json:"key_scope"`
	KeyName         string                        `json:"key_name"`
	KeyGeneration   uint64                        `json:"key_generation"`
	Desired         enrollment.SignedDesiredState `json:"desired"`
	State           string                        `json:"state"`
	EnrollmentID    string                        `json:"enrollment_id,omitempty"`
	ExpiresAt       int64                         `json:"expires_at,omitempty"`
	CreatedAt       time.Time                     `json:"created_at"`
	UpdatedAt       time.Time                     `json:"updated_at"`
	RotationPending bool                          `json:"rotation_pending,omitempty"`
	Host            string                        `json:"host,omitempty"`
	SSHUser         string                        `json:"ssh_user,omitempty"`
	SSHPort         int                           `json:"ssh_port,omitempty"`
}

func commandEnroll(ctx *commandContext, args []string) int {
	if len(args) == 0 {
		return usage(ctx, "usage: flow enroll <create|list|revoke>")
	}
	switch args[0] {
	case "create":
		return enrollCreate(ctx, args[1:])
	case "list":
		return enrollList(ctx, args[1:])
	case "revoke":
		return enrollRevoke(ctx, args[1:])
	default:
		return usage(ctx, "unknown enroll command: "+args[0])
	}
}

func enrollCreate(ctx *commandContext, args []string) int {
	flags := flag.NewFlagSet("enroll create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	name := flags.String("name", "", "instance name")
	profile := flags.String("profile", "", "declarative profile")
	operatorKey := flags.String("key", "", "existing operator SSH key instead of a per-instance key")
	ttl := flags.Duration("ttl", 15*time.Minute, "one-time enrollment lifetime")
	host := flags.String("host", "", "reachable SSH host or address (no connection is made)")
	sshUser := flags.String("ssh-user", "", "existing non-root SSH administrator")
	sshPort := flags.Int("ssh-port", 22, "SSH port")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *name == "" || *profile == "" || *ttl < time.Minute || *ttl > 24*time.Hour {
		return usage(ctx, "usage: flow enroll create --name NAME --profile PROFILE [--host HOST --ssh-user USER [--ssh-port 22]] [--key OPERATOR-KEY] [--ttl 15m]")
	}
	if (*host == "") != (*sshUser == "") {
		return usage(ctx, "--host and --ssh-user must be supplied together")
	}
	if *host != "" {
		normalized, endpointErr := instances.ValidateEndpoint(*host, *sshUser, *sshPort)
		if endpointErr != nil {
			return ctx.out.fail("ssh_endpoint", endpointErr.Error(), "Provide a reachable host, a non-root administrator and port 1..65535.", exitConfig)
		}
		*host = normalized
	} else if *sshPort != 22 {
		return usage(ctx, "--ssh-port requires --host and --ssh-user")
	}
	registry, err := loadProfiles(ctx)
	if err != nil {
		return ctx.out.fail("profile", err.Error(), "Repair the declarative profile graph.", exitConfig)
	}
	resolved, err := registry.Resolve(*profile)
	if err != nil {
		return ctx.out.fail("profile", err.Error(), "Choose a profile shown by flow profile list.", exitConfig)
	}
	requested, _ := registry.Get(*profile)
	if !requested.Installable {
		return ctx.out.fail("profile_unavailable", "profile is declarative-only and has no fixed target executor", "Choose an installable profile; Decepticon and Examstation remain classified but cannot be enrolled yet.", exitConfig)
	}
	remote, err := loadRemoteServing(ctx)
	if err != nil {
		return ctx.out.fail("serving", err.Error(), "Run flow serving configure first.", exitConfig)
	}
	ctx.out.phase("release", "running", "verifying active release and profile")
	var current release.SignedManifest
	operation, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := remote.publicJSON(operation, "GET", "/v1/releases/current/manifest", &current); err != nil {
		return ctx.out.fail("release", safeRemoteError(err), "Check flow status serving and the pinned connection.", exitRemote)
	}
	releasePublicPath, _ := ctx.store.Path("keys/signing/release.public.pem")
	releasePublic, err := signing.LoadPublicFile(releasePublicPath)
	if err == nil {
		err = release.VerifyManifest(current, releasePublic)
	}
	if err != nil || !releaseHasProfile(current.Manifest, *profile) {
		return ctx.out.fail("release", "active signed release does not contain the requested profile", "Build/publish a release containing the profile.", exitVerify)
	}
	if err := acceptOperatorReleaseHighWater(ctx, current.Manifest); err != nil {
		return ctx.out.fail("release_rollback", err.Error(), "Restore serving to the newest operator-accepted signed release.", exitVerify)
	}
	manager := sshkeys.NewManager(ctx.store)
	keyScope, keyName := sshkeys.Instance, *name
	if *operatorKey != "" {
		keyScope, keyName = sshkeys.Operator, *operatorKey
	}
	keyRecord, err := manager.Get(keyScope, keyName)
	if errors.Is(err, sshkeys.ErrNotFound) && keyScope == sshkeys.Instance {
		ctx.out.phase("ssh-key", "running", "creating dedicated per-instance Ed25519 key")
		keyOperation, keyCancel := context.WithTimeout(context.Background(), 30*time.Second)
		keyRecord, err = manager.Create(keyOperation, keyScope, keyName)
		keyCancel()
	}
	if err != nil || keyRecord.Status != sshkeys.ActiveStatus {
		return ctx.out.fail("ssh_key", fmt.Sprintf("could not select active SSH key: %v", err), "Create/repair the local key; private material must remain on this operator.", exitAuth)
	}
	desiredPrivatePath, _ := ctx.store.Path("keys/signing/desired-state.private.pem")
	desiredPublicPath, _ := ctx.store.Path("keys/signing/desired-state.public.pem")
	desiredPrivate, desiredPublic, err := loadSigningPair(desiredPrivatePath, desiredPublicPath)
	if err != nil {
		return ctx.out.fail("desired_signing", err.Error(), "Restore the offline desired-state signing key.", exitAuth)
	}
	desiredKeyID, _ := signing.KeyID(desiredPublic)
	if desiredKeyID != remote.config.DesiredKeyID {
		return ctx.out.fail("trust", "desired-state key differs from pinned serving binding", "Reconcile serving with the correct public key.", exitVerify)
	}
	metadataPath := filepath.Join("enrollments", *name+".json")
	var local localEnrollment
	readErr := ctx.store.ReadJSON(metadataPath, &local)
	now := time.Now().UTC()
	needNewDesired := false
	switch {
	case readErr == nil:
		if local.Schema != 1 || local.Name != *name || local.Profile != *profile || local.KeyScope != keyScope || local.KeyName != keyName || local.KeyGeneration != keyRecord.Generation ||
			local.Host != *host || local.SSHUser != *sshUser || local.SSHPort != endpointPort(*host, *sshPort) {
			return ctx.out.fail("conflict", "existing enrollment draft has different instance/profile/key binding", "Use a new instance name or explicitly revoke the old enrollment.", exitConflict)
		}
		if local.State == "issued" {
			return ctx.out.fail("conflict", "enrollment secret was already issued and is never stored locally", "Use flow enroll list; wait for expiry or revoke before creating a replacement.", exitConflict)
		}
		if local.State != "draft" {
			return ctx.out.fail("state", "invalid local enrollment state", "Repair the private state from audit evidence.", exitConfig)
		}
		if local.Desired.State.ReleaseSet != current.Manifest.SetID || now.Unix() >= local.Desired.State.ExpiresAt {
			needNewDesired = true
		}
	case errors.Is(readErr, os.ErrNotExist):
		local = localEnrollment{
			Schema: 1, Name: *name, Profile: *profile, KeyScope: keyScope, KeyName: keyName,
			KeyGeneration: keyRecord.Generation, State: "draft", CreatedAt: now,
			Host: *host, SSHUser: *sshUser, SSHPort: endpointPort(*host, *sshPort),
		}
		needNewDesired = true
	default:
		return ctx.out.fail("state", readErr.Error(), "Repair local enrollment metadata.", exitConfig)
	}
	if needNewDesired {
		generation := uint64(1)
		if local.Desired.State.Generation > 0 {
			generation = local.Desired.State.Generation + 1
		}
		signed, err := enrollment.SignDesiredState(enrollment.DesiredState{
			Schema: enrollment.DesiredStateSchema, Instance: *name, Profile: *profile,
			Generation: generation, ReleaseSet: current.Manifest.SetID,
			AuthorizedSSHKeys: []string{keyRecord.PublicKey}, IssuedAt: now.Unix(), ExpiresAt: now.Add(90 * 24 * time.Hour).Unix(),
		}, desiredPrivate)
		if err != nil {
			return ctx.out.fail("desired_signing", err.Error(), "Validate instance, profile and SSH public key.", exitVerify)
		}
		local.Desired = signed
		local.UpdatedAt = now
		if err := ctx.store.WriteJSON(metadataPath, local); err != nil {
			return ctx.out.fail("state", err.Error(), "Repair private state permissions; no code was requested.", exitConfig)
		}
	}
	ctx.out.phase("enrollment", "running", "requesting one-time credential over pinned HTTPS")
	if err := audit(ctx, "enroll.create", "started", map[string]any{"instance": *name, "profile": *profile}); err != nil {
		return ctx.out.fail("audit_unavailable", "local audit event could not be committed; enrollment was not requested", "Repair the private audit log and retry.", exitFailure)
	}
	request := serving.AdminEnrollmentCreateRequest{Desired: local.Desired, TTLSeconds: int64(*ttl / time.Second)}
	var response serving.AdminEnrollmentCreateResponse
	if err := remote.controlJSON(operation, "POST", "/v1/admin/enrollments", request, &response, 201); err != nil {
		audit(ctx, "enroll.create", "failure", map[string]any{"instance": *name, "profile": *profile, "error_code": safeRemoteError(err)})
		return ctx.out.fail("enrollment", safeRemoteError(err), "The secret was not persisted. Inspect flow enroll list; retry the same draft after any live code expires.", exitRemote)
	}
	if response.Instance != *name || response.Profile != *profile || !validURLToken(response.EnrollmentID, 16) || !validURLToken(response.Secret, 32) || response.ExpiresAt <= now.Unix() {
		enrollmentID := response.EnrollmentID
		response.Secret = ""
		if validURLToken(enrollmentID, 16) {
			revokeContext, revokeCancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, revokeErr := revokeRemoteEnrollment(revokeContext, remote, enrollmentID)
			revokeCancel()
			if revokeErr == nil {
				_ = audit(ctx, "enroll.create", "invalid_response_revoked", map[string]any{"instance": *name, "profile": *profile})
				return ctx.out.fail("verification", "serving returned an invalid enrollment credential; its valid public ID was revoked", "Inspect serving audit logs before retrying the existing local draft.", exitVerify)
			}
			_ = audit(ctx, "enroll.create", "invalid_response_revoke_failed", map[string]any{"instance": *name, "profile": *profile})
			return ctx.out.fail("verification", "serving returned an invalid enrollment credential and automatic revocation failed", "Inspect flow enroll list and revoke the live public ID before retrying.", exitPartial)
		}
		_ = audit(ctx, "enroll.create", "invalid_response_unidentified", map[string]any{"instance": *name, "profile": *profile})
		return ctx.out.fail("verification", "serving returned an invalid enrollment credential without a safe revocation identifier", "Inspect serving enrollment and audit state; revoke any matching live credential before retrying.", exitPartial)
	}
	local.State, local.EnrollmentID, local.ExpiresAt, local.UpdatedAt = "issued", response.EnrollmentID, response.ExpiresAt, time.Now().UTC()
	if err := ctx.store.WriteJSON(metadataPath, local); err != nil {
		enrollmentID := response.EnrollmentID
		response.Secret = ""
		revokeContext, revokeCancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, revokeErr := revokeRemoteEnrollment(revokeContext, remote, enrollmentID)
		revokeCancel()
		if revokeErr == nil {
			return ctx.out.fail("state", "credential metadata could not be stored; the newly issued credential was revoked", "Repair local state and retry the existing draft.", exitPartial)
		}
		return ctx.out.fail("state", "credential was issued but metadata storage and automatic revocation both failed", "Immediately run flow enroll revoke --id "+enrollmentID+" after repairing local audit/state access.", exitPartial)
	}
	audit(ctx, "enroll.create", "success", map[string]any{
		"instance": *name, "profile": *profile, "expires_at": response.ExpiresAt,
		"key_fingerprint": keyRecord.Fingerprint,
	})
	data := map[string]any{
		"instance": response.Instance, "profile": response.Profile, "enrollment_id": response.EnrollmentID,
		"secret": response.Secret, "expires_at": response.ExpiresAt, "ssh_key_fingerprint": keyRecord.Fingerprint,
		"resolved_profiles": resolved, "bootstrap_url": remote.config.BaseURL + "/bootstrap",
		"ssh_host": local.Host, "ssh_user": local.SSHUser, "ssh_port": local.SSHPort,
	}
	human := fmt.Sprintf("Enrollment for %s (%s) created.\nID: %s\nSecret (shown once; enter only at the VM prompt): %s\nExpires: %s\nBootstrap: curl --fail --insecure %s/bootstrap | sudo sh\nWARNING: the quickstart curl trusts the first script download; use the pinned hardened path from the runbook for hostile networks.",
		response.Instance, response.Profile, response.EnrollmentID, response.Secret, time.Unix(response.ExpiresAt, 0).UTC().Format(time.RFC3339), remote.config.BaseURL)
	return ctx.out.success("enroll.create", data, human)
}

func endpointPort(host string, port int) int {
	if host == "" {
		return 0
	}
	return port
}

func enrollList(ctx *commandContext, args []string) int {
	flags := flag.NewFlagSet("enroll list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return usage(ctx, "usage: flow enroll list")
	}
	remote, err := loadRemoteServing(ctx)
	if err != nil {
		return ctx.out.fail("serving", err.Error(), "Run flow serving configure first.", exitConfig)
	}
	var response struct {
		Enrollments []enrollment.Record `json:"enrollments"`
	}
	operation, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := remote.controlJSON(operation, "GET", "/v1/admin/enrollments", nil, &response, 200); err != nil {
		return ctx.out.fail("enrollment", safeRemoteError(err), "Check serving status and control-key binding.", exitRemote)
	}
	if !ctx.out.json {
		now := time.Now().UTC().Unix()
		for _, record := range response.Enrollments {
			state := "pending"
			switch {
			case record.RevokedAt != 0:
				state = "revoked"
			case record.ConsumedAt != 0:
				state = "consumed"
			case record.ExpiresAt <= now:
				state = "expired"
			}
			fmt.Fprintf(ctx.out.stdout, "%-20s %-12s %-10s expires=%s id=%s\n", record.Instance, record.Profile, state, time.Unix(record.ExpiresAt, 0).UTC().Format(time.RFC3339), record.ID)
		}
		return exitOK
	}
	return ctx.out.success("enroll.list", response.Enrollments, "")
}

func enrollRevoke(ctx *commandContext, args []string) int {
	flags := flag.NewFlagSet("enroll revoke", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("id", "", "public enrollment identifier")
	name := flags.String("name", "", "instance name used to find one live enrollment")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || (*id == "") == (*name == "") {
		return usage(ctx, "usage: flow enroll revoke (--id ID | --name NAME)")
	}
	remote, err := loadRemoteServing(ctx)
	if err != nil {
		return ctx.out.fail("serving", err.Error(), "Run flow serving configure first.", exitConfig)
	}
	operation, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if *name != "" {
		if !validLifecycleName(*name) {
			return usage(ctx, "usage: flow enroll revoke (--id ID | --name NAME)")
		}
		var response struct {
			Enrollments []enrollment.Record
		}
		if err := remote.controlJSON(operation, "GET", "/v1/admin/enrollments", nil, &response, 200); err != nil {
			return ctx.out.fail("enrollment", safeRemoteError(err), "Check serving status and control-key binding.", exitRemote)
		}
		for _, record := range response.Enrollments {
			if record.Instance == *name && record.ConsumedAt == 0 && record.RevokedAt == 0 {
				if *id != "" {
					return ctx.out.fail("conflict", "instance has multiple live enrollment records", "Revoke each explicit public enrollment ID.", exitConflict)
				}
				*id = record.ID
			}
		}
		if *id == "" {
			return ctx.out.fail("enrollment_not_found", "instance has no live unconsumed enrollment", "Run flow enroll list.", exitConfig)
		}
	}
	if !validURLToken(*id, 16) {
		return ctx.out.fail("enrollment", "invalid public enrollment identifier", "Copy the ID from flow enroll list; never provide the secret.", exitConfig)
	}
	if err := audit(ctx, "enroll.revoke", "started", map[string]any{"enrollment_id": *id}); err != nil {
		return ctx.out.fail("audit_unavailable", "local audit event could not be committed; enrollment was not revoked", "Repair the private audit log and retry.", exitFailure)
	}
	record, err := revokeRemoteEnrollment(operation, remote, *id)
	if err != nil {
		return ctx.out.fail("enrollment", safeRemoteError(err), "Run flow enroll list; consumed enrollments require instance revocation.", exitRemote)
	}
	if local, localErr := loadLocalEnrollment(ctx, record.Instance); localErr == nil && local.EnrollmentID == record.ID && local.State == "issued" {
		local.State, local.EnrollmentID, local.ExpiresAt, local.UpdatedAt = "draft", "", 0, time.Now().UTC()
		if err := saveLocalEnrollment(ctx, local); err != nil {
			return ctx.out.fail("state", "serving revoked the enrollment but local metadata was not updated", "Repair local state, then retry enrollment creation for the same draft.", exitPartial)
		}
	}
	_ = audit(ctx, "enroll.revoke", "success", map[string]any{"enrollment_id": record.ID, "instance": record.Instance})
	return ctx.out.success("enroll.revoke", map[string]any{
		"enrollment_id": record.ID, "instance": record.Instance, "profile": record.Profile, "revoked": true,
	}, fmt.Sprintf("Revoked unconsumed enrollment %s for %s.", record.ID, record.Instance))
}

func revokeRemoteEnrollment(ctx context.Context, remote *remoteServing, id string) (enrollment.Record, error) {
	var record enrollment.Record
	if !validURLToken(id, 16) {
		return record, errors.New("invalid enrollment identifier")
	}
	err := remote.controlJSON(ctx, "POST", "/v1/admin/enrollments/"+id+"/revoke", nil, &record, 202)
	if err != nil {
		return record, err
	}
	if record.ID != id || record.RevokedAt == 0 || record.ConsumedAt != 0 {
		return record, errors.New("serving returned an invalid enrollment revocation")
	}
	return record, nil
}

func releaseHasProfile(manifest release.Manifest, name string) bool {
	for _, profile := range manifest.Profiles {
		if profile.Name == name {
			return true
		}
	}
	return false
}

func validURLToken(value string, size int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == size && value == base64.RawURLEncoding.EncodeToString(decoded) && !strings.ContainsAny(value, "\r\n\x00")
}
