package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"dynamicflow/internal/release"
	"dynamicflow/internal/servingruntime"
	"dynamicflow/internal/signing"
)

const servingPlanSchema = 1

type servingPlanInput struct {
	StateRoot         string
	ReleaseRoot       string
	Listen            string
	PublicURL         string
	ReleaseKeySource  string
	DesiredKeySource  string
	ControlKeySource  string
	ServiceUser       string
	ReleasePublic     ed25519.PublicKey
	DesiredPublic     ed25519.PublicKey
	ControlPublic     ed25519.PublicKey
	Current           release.SignedManifest
	ExistingReference localServingReference
	ReferenceExists   bool
}

type servingPlanAccount struct {
	UID int
	GID int
}

type servingPlanServiceState struct {
	Available    bool
	Enabled      bool
	Active       bool
	Loaded       bool
	FragmentPath string
	NeedsReload  bool
}

type servingPlanEnvironment struct {
	UnitPath       string
	ExecutablePath string
	RootUID        int
	RootGID        int
	LookupAccount  func(string) (servingPlanAccount, bool, error)
	ServiceState   func(string) servingPlanServiceState
}

type servingReconcilePlan struct {
	Schema         int                `json:"schema"`
	Plan           bool               `json:"plan"`
	State          string             `json:"state"`
	Changed        bool               `json:"changed"`
	Unsafe         bool               `json:"unsafe"`
	Complete       bool               `json:"complete"`
	Applicable     bool               `json:"applicable"`
	StateRoot      string             `json:"state_root"`
	ReleaseRoot    string             `json:"release_root"`
	PublicURL      string             `json:"public_url"`
	Listen         string             `json:"listen"`
	ServiceUser    string             `json:"service_user"`
	ReleaseSet     string             `json:"release_set"`
	ReleaseKeyID   string             `json:"release_key_id"`
	DesiredKeyID   string             `json:"desired_key_id"`
	ControlKeyID   string             `json:"control_key_id"`
	TLSFingerprint string             `json:"tls_fingerprint,omitempty"`
	Summary        servingPlanSummary `json:"summary"`
	Items          []servingPlanItem  `json:"items"`
}

type servingPlanSummary struct {
	Noop    int `json:"noop"`
	Changes int `json:"changes"`
	Unsafe  int `json:"unsafe"`
	Unknown int `json:"unknown"`
}

type servingPlanItem struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Action  string `json:"action"`
	Path    string `json:"path,omitempty"`
	Actual  string `json:"actual"`
	Desired string `json:"desired"`
	Detail  string `json:"detail,omitempty"`
}

type servingPlanMetadata struct {
	Mode     os.FileMode
	UID      int
	GID      int
	CheckUID bool
	CheckGID bool
}

type servingPlanPath struct {
	Exists  bool
	Info    os.FileInfo
	Unsafe  string
	Unknown string
}

func defaultServingPlanEnvironment() servingPlanEnvironment {
	executable, _ := os.Executable()
	if executable != "" {
		executable, _ = filepath.Abs(executable)
	}
	return servingPlanEnvironment{
		UnitPath:       filepath.Join("/etc/systemd/system", servingServiceName),
		ExecutablePath: executable,
		RootUID:        0,
		RootGID:        0,
		LookupAccount:  inspectServingPlanAccount,
		ServiceState:   inspectServingPlanServiceState,
	}
}

func commandServingPlan(ctx *commandContext, input servingPlanInput, environment servingPlanEnvironment) int {
	plan, err := buildServingReconcilePlan(ctx, input, environment)
	if err != nil {
		return ctx.out.fail("plan", err.Error(), "Repair the verified release or public trust inputs and retry the read-only plan.", exitVerify)
	}
	human := formatServingPlan(plan)
	if plan.Unsafe {
		if !ctx.out.json {
			fmt.Fprintln(ctx.out.stdout, human)
		}
		return ctx.out.failData("start.serving.plan", plan, "unsafe_state", "serving contains an unsafe existing path or identity", "Repair only the listed unsafe resource; no changes were made.", exitConfig)
	}
	return ctx.out.success("start.serving.plan", plan, human)
}

func buildServingReconcilePlan(ctx *commandContext, input servingPlanInput, environment servingPlanEnvironment) (servingReconcilePlan, error) {
	plan := servingReconcilePlan{
		Schema: servingPlanSchema, Plan: true, Complete: true, Applicable: true,
		StateRoot: input.StateRoot, ReleaseRoot: input.ReleaseRoot, PublicURL: strings.TrimSuffix(input.PublicURL, "/"),
		Listen: input.Listen, ServiceUser: input.ServiceUser, ReleaseSet: input.Current.Manifest.SetID,
	}
	if ctx == nil || ctx.store == nil || environment.LookupAccount == nil || environment.ServiceState == nil {
		return plan, errors.New("invalid serving plan context")
	}
	var err error
	if plan.ReleaseKeyID, err = signing.KeyID(input.ReleasePublic); err != nil {
		return plan, err
	}
	if plan.DesiredKeyID, err = signing.KeyID(input.DesiredPublic); err != nil {
		return plan, err
	}
	if plan.ControlKeyID, err = signing.KeyID(input.ControlPublic); err != nil {
		return plan, err
	}
	releasePEM, err := signing.MarshalPublicPEM(input.ReleasePublic)
	if err != nil {
		return plan, err
	}
	desiredPEM, err := signing.MarshalPublicPEM(input.DesiredPublic)
	if err != nil {
		return plan, err
	}
	controlPEM, err := signing.MarshalPublicPEM(input.ControlPublic)
	if err != nil {
		return plan, err
	}
	plan.add(planServingPublicKeySource("source.release_key", input.ReleaseKeySource, plan.ReleaseKeyID))
	plan.add(planServingPublicKeySource("source.desired_key", input.DesiredKeySource, plan.DesiredKeyID))
	plan.add(planServingPublicKeySource("source.control_key", input.ControlKeySource, plan.ControlKeyID))

	account, accountExists, accountErr := environment.LookupAccount(input.ServiceUser)
	switch {
	case errors.Is(accountErr, os.ErrPermission) || errors.Is(accountErr, syscall.EACCES) || errors.Is(accountErr, syscall.EPERM):
		plan.add(servingPlanItem{ID: "account.service", Status: "unknown", Action: "verify_on_apply", Actual: "protected", Desired: "locked dedicated system account", Detail: "password-lock verification requires root"})
	case accountErr != nil:
		plan.add(servingPlanItem{ID: "account.service", Status: "unsafe", Action: "manual_repair", Actual: "invalid", Desired: "locked dedicated system account", Detail: "existing account does not satisfy the serving identity policy"})
	case !accountExists:
		plan.add(servingPlanItem{ID: "account.service", Status: "change", Action: "create", Actual: "missing", Desired: "locked dedicated system account"})
	default:
		plan.add(servingPlanItem{ID: "account.service", Status: "noop", Action: "none", Actual: fmt.Sprintf("uid=%d gid=%d locked", account.UID, account.GID), Desired: "locked dedicated system account"})
	}

	serviceUID, serviceGID := account.UID, account.GID
	accountPermissionLimited := errors.Is(accountErr, os.ErrPermission) || errors.Is(accountErr, syscall.EACCES) || errors.Is(accountErr, syscall.EPERM)
	serviceOwnerKnown := accountExists && (accountErr == nil || accountPermissionLimited)
	directories := []struct {
		id       string
		path     string
		metadata servingPlanMetadata
	}{
		{"directory.state", input.StateRoot, servingPlanMetadata{Mode: 0o751, UID: environment.RootUID, GID: serviceGID, CheckUID: true, CheckGID: serviceOwnerKnown}},
		{"directory.releases", input.ReleaseRoot, servingPlanMetadata{Mode: 0o755, UID: serviceUID, GID: serviceGID, CheckUID: serviceOwnerKnown, CheckGID: serviceOwnerKnown}},
		{"directory.releases.sets", filepath.Join(input.ReleaseRoot, "sets"), servingPlanMetadata{Mode: 0o755, UID: serviceUID, GID: serviceGID, CheckUID: serviceOwnerKnown, CheckGID: serviceOwnerKnown}},
		{"directory.releases.history", filepath.Join(input.ReleaseRoot, "history"), servingPlanMetadata{Mode: 0o755, UID: serviceUID, GID: serviceGID, CheckUID: serviceOwnerKnown, CheckGID: serviceOwnerKnown}},
		{"directory.releases.imports", filepath.Join(input.ReleaseRoot, ".imports"), servingPlanMetadata{Mode: 0o700, UID: serviceUID, GID: serviceGID, CheckUID: serviceOwnerKnown, CheckGID: serviceOwnerKnown}},
		{"directory.trust", filepath.Join(input.StateRoot, "trust"), servingPlanMetadata{Mode: 0o755, UID: environment.RootUID, GID: serviceGID, CheckUID: true, CheckGID: serviceOwnerKnown}},
		{"directory.tls", filepath.Join(input.StateRoot, "tls"), servingPlanMetadata{Mode: 0o750, UID: environment.RootUID, GID: serviceGID, CheckUID: true, CheckGID: serviceOwnerKnown}},
		{"directory.private", filepath.Join(input.StateRoot, "private"), servingPlanMetadata{Mode: 0o700, UID: serviceUID, GID: serviceGID, CheckUID: serviceOwnerKnown, CheckGID: serviceOwnerKnown}},
		{"directory.private.desired", filepath.Join(input.StateRoot, "private", "desired"), servingPlanMetadata{Mode: 0o700, UID: serviceUID, GID: serviceGID, CheckUID: serviceOwnerKnown, CheckGID: serviceOwnerKnown}},
		{"directory.private.logs", filepath.Join(input.StateRoot, "private", "logs"), servingPlanMetadata{Mode: 0o700, UID: serviceUID, GID: serviceGID, CheckUID: serviceOwnerKnown, CheckGID: serviceOwnerKnown}},
		{"directory.private.status", filepath.Join(input.StateRoot, "private", "status"), servingPlanMetadata{Mode: 0o700, UID: serviceUID, GID: serviceGID, CheckUID: serviceOwnerKnown, CheckGID: serviceOwnerKnown}},
	}
	for _, directory := range directories {
		plan.add(planServingDirectory(directory.id, directory.path, directory.metadata))
	}
	plan.add(planServingFile("release.publish_lock", filepath.Join(input.ReleaseRoot, ".publish.lock"), nil,
		servingPlanMetadata{Mode: 0o600, UID: serviceUID, GID: serviceGID, CheckUID: serviceOwnerKnown, CheckGID: serviceOwnerKnown},
		"dedicated serving publication lock"))
	plan.add(servingPlanItem{ID: "release.current", Status: "noop", Action: "none", Path: input.ReleaseRoot, Actual: input.Current.Manifest.SetID, Desired: input.Current.Manifest.SetID, Detail: "signature and immutable artifacts verified"})

	publicTrustMetadata := servingPlanMetadata{Mode: 0o644, UID: environment.RootUID, GID: serviceGID, CheckUID: true, CheckGID: serviceOwnerKnown}
	controlledMetadata := servingPlanMetadata{Mode: 0o640, UID: environment.RootUID, GID: serviceGID, CheckUID: true, CheckGID: serviceOwnerKnown}
	trustDir := filepath.Join(input.StateRoot, "trust")
	plan.add(planServingFile("trust.release", filepath.Join(trustDir, "release.public.pem"), releasePEM, publicTrustMetadata, "ed25519:"+plan.ReleaseKeyID))
	plan.add(planServingFile("trust.desired", filepath.Join(trustDir, "desired-state.public.pem"), desiredPEM, publicTrustMetadata, "ed25519:"+plan.DesiredKeyID))
	plan.add(planServingFile("trust.control", filepath.Join(trustDir, "control.public.pem"), controlPEM, publicTrustMetadata, "ed25519:"+plan.ControlKeyID))

	tlsCert := filepath.Join(input.StateRoot, "tls", "serving.crt")
	tlsKey := filepath.Join(input.StateRoot, "tls", "serving.key")
	certPath := inspectServingPlanPath(tlsCert, false)
	keyPath := inspectServingPlanPath(tlsKey, false)
	plan.add(planServingMetadataFile("tls.certificate", tlsCert, certPath, servingPlanMetadata{Mode: 0o644, UID: environment.RootUID, GID: serviceGID, CheckUID: true, CheckGID: serviceOwnerKnown}, "serving transport certificate"))
	plan.add(planServingMetadataFile("tls.private_key", tlsKey, keyPath, controlledMetadata, "protected serving transport private key"))

	var certData []byte
	tlsReady := false
	switch {
	case certPath.Unsafe != "" || keyPath.Unsafe != "":
		plan.add(servingPlanItem{ID: "tls.identity", Status: "unsafe", Action: "manual_repair", Actual: "unsafe path", Desired: "complete matching certificate/private-key pair"})
	case certPath.Unknown != "" || keyPath.Unknown != "":
		plan.add(servingPlanItem{ID: "tls.identity", Status: "unknown", Action: "verify_on_apply", Actual: "protected", Desired: "complete matching certificate/private-key pair", Detail: "identity metadata requires serving-file access"})
	case certPath.Exists != keyPath.Exists:
		plan.add(servingPlanItem{ID: "tls.identity", Status: "unsafe", Action: "restore_pair", Actual: "incomplete pair", Desired: "complete matching certificate/private-key pair", Detail: "flow never replaces one half of an existing TLS identity"})
	case !certPath.Exists:
		plan.add(servingPlanItem{ID: "tls.identity", Status: "change", Action: "create", Actual: "missing", Desired: "new serving-only self-signed identity"})
	default:
		if err := validateServingPlanTLSPair(tlsCert, tlsKey); err != nil {
			if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) {
				plan.add(servingPlanItem{ID: "tls.identity", Status: "unknown", Action: "verify_on_apply", Actual: "protected", Desired: "matching certificate/private-key pair", Detail: "private-key comparison requires serving-file read access"})
			} else {
				plan.add(servingPlanItem{ID: "tls.identity", Status: "unsafe", Action: "restore_pair", Actual: "invalid or mismatched", Desired: "matching certificate/private-key pair"})
			}
		} else if err := validateServingPlanTLSHost(tlsCert, input.PublicURL); err != nil {
			plan.add(servingPlanItem{ID: "tls.identity", Status: "unsafe", Action: "restore_pair", Actual: "certificate does not cover public serving host", Desired: "matching certificate/private-key pair for public_url"})
		} else {
			certData, err = readServingPlanFile(tlsCert, 1<<20)
			if err != nil {
				plan.add(servingPlanItem{ID: "tls.identity", Status: "unknown", Action: "verify_on_apply", Actual: "protected", Desired: "matching certificate/private-key pair"})
			} else {
				fingerprint, fingerprintErr := servingPlanTLSFingerprint(certData)
				if fingerprintErr != nil {
					plan.add(servingPlanItem{ID: "tls.identity", Status: "unsafe", Action: "restore_pair", Actual: "invalid certificate", Desired: "matching certificate/private-key pair"})
				} else {
					plan.TLSFingerprint = fingerprint
					tlsReady = true
					plan.add(servingPlanItem{ID: "tls.identity", Status: "noop", Action: "preserve", Actual: fingerprint, Desired: "preserve existing matching identity"})
				}
			}
		}
	}

	config := desiredServingConfig(input.StateRoot, input.ReleaseRoot, input.Listen, input.PublicURL)
	if err := servingruntime.Validate(config); err != nil {
		return plan, err
	}
	configData, err := signing.CanonicalJSON(config)
	if err != nil {
		return plan, err
	}
	plan.add(planServingFile("config.runtime", filepath.Join(input.StateRoot, "config.json"), configData, controlledMetadata, "canonical serving runtime configuration"))

	bootstrapPath := filepath.Join(input.StateRoot, "bootstrap.sh")
	if tlsReady {
		bootstrap, bootstrapErr := buildBootstrapFromData(input.PublicURL, input.Current, plan.TLSFingerprint, certData, releasePEM, desiredPEM)
		if bootstrapErr != nil {
			return plan, bootstrapErr
		}
		plan.add(planServingFile("bootstrap.script", bootstrapPath, bootstrap, controlledMetadata, "hash-pinned bootstrap for "+input.Current.Manifest.SetID))
	} else {
		plan.add(planServingDeferredFile("bootstrap.script", bootstrapPath, "generate_after_tls", "hash-pinned bootstrap for "+input.Current.Manifest.SetID))
	}

	executableUsable := planServingExecutable(&plan, environment.ExecutablePath, environment.RootUID)
	unitPath := inspectServingPlanPath(environment.UnitPath, false)
	unitPathsSafe := safeServingUnitPath(environment.ExecutablePath) && safeServingUnitPath(input.StateRoot) && safeServingUnitPath(input.ReleaseRoot)
	if !unitPathsSafe {
		plan.add(servingPlanItem{ID: "service.unit", Status: "unsafe", Action: "choose_safe_paths", Path: environment.UnitPath, Actual: "ExecStart or state path contains unsafe whitespace", Desired: "hardened systemd unit with unambiguous absolute paths"})
	} else if serviceOwnerKnown && executableUsable {
		unit := []byte(servingUnit(environment.ExecutablePath, filepath.Join(input.StateRoot, "config.json"), input.StateRoot, input.ReleaseRoot, input.ServiceUser, strconv.Itoa(serviceGID)))
		plan.add(planServingFileWithState("service.unit", environment.UnitPath, unit, servingPlanMetadata{Mode: 0o644, UID: environment.RootUID, GID: environment.RootGID, CheckUID: true, CheckGID: true}, "hardened systemd unit", unitPath))
	} else {
		if unitPath.Unsafe != "" {
			plan.add(servingPlanItem{ID: "service.unit", Status: "unsafe", Action: "manual_repair", Path: environment.UnitPath, Actual: unitPath.Unsafe, Desired: "hardened systemd unit"})
		} else if unitPath.Unknown != "" {
			plan.add(servingPlanItem{ID: "service.unit", Status: "unknown", Action: "verify_on_apply", Path: environment.UnitPath, Actual: unitPath.Unknown, Desired: "hardened systemd unit"})
		} else {
			plan.add(planServingDeferredFile("service.unit", environment.UnitPath, "render_after_prerequisites", "hardened systemd unit"))
		}
	}

	if tlsReady {
		desiredReference := localServingReference{
			Schema: localServingReferenceSchema, ConfigPath: filepath.Join(input.StateRoot, "config.json"), StateRoot: input.StateRoot,
			ReleaseRoot: input.ReleaseRoot, ReleasePublicKeySource: input.ReleaseKeySource,
			DesiredPublicKeySource: input.DesiredKeySource, ControlPublicKeySource: input.ControlKeySource,
			ServiceUser: input.ServiceUser, PublicURL: strings.TrimSuffix(input.PublicURL, "/"), Listen: input.Listen,
			Fingerprint: plan.TLSFingerprint,
		}
		if input.ReferenceExists && input.ExistingReference == desiredReference {
			plan.add(servingPlanItem{ID: "operator.reference", Status: "noop", Action: "none", Actual: "matches desired trust paths", Desired: "matching local serving reference"})
		} else if input.ReferenceExists {
			plan.add(servingPlanItem{ID: "operator.reference", Status: "change", Action: "update", Actual: "drifted", Desired: "matching local serving reference"})
		} else {
			plan.add(servingPlanItem{ID: "operator.reference", Status: "change", Action: "create", Actual: "missing", Desired: "matching local serving reference"})
		}
	} else {
		action := "create_after_tls"
		actual := "missing"
		status := "change"
		if input.ReferenceExists {
			action = "verify_on_apply"
			actual = "present; TLS binding pending"
			status = "unknown"
		}
		plan.add(servingPlanItem{ID: "operator.reference", Status: status, Action: action, Actual: actual, Desired: "matching local serving reference"})
	}

	state := environment.ServiceState(servingServiceName)
	if !state.Available {
		plan.add(servingPlanItem{ID: "service.definition", Status: "unknown", Action: "verify_on_apply", Actual: "systemd unit state unavailable", Desired: "loaded from " + environment.UnitPath})
	} else if !state.Loaded {
		plan.add(servingPlanItem{ID: "service.definition", Status: "change", Action: "daemon_reload", Actual: "not loaded", Desired: "loaded from " + environment.UnitPath})
	} else if state.FragmentPath != environment.UnitPath {
		plan.add(servingPlanItem{ID: "service.definition", Status: "change", Action: "reload_definition", Actual: "loaded from " + state.FragmentPath, Desired: "loaded from " + environment.UnitPath})
	} else if state.NeedsReload {
		plan.add(servingPlanItem{ID: "service.definition", Status: "change", Action: "daemon_reload", Actual: "loaded definition is stale", Desired: "loaded current unit definition"})
	} else {
		plan.add(servingPlanItem{ID: "service.definition", Status: "noop", Action: "none", Actual: "loaded from " + state.FragmentPath, Desired: "loaded current unit definition"})
	}
	if !state.Available {
		plan.add(servingPlanItem{ID: "service.enabled", Status: "unknown", Action: "verify_on_apply", Actual: "systemd state unavailable", Desired: "enabled"})
	} else if state.Enabled {
		plan.add(servingPlanItem{ID: "service.enabled", Status: "noop", Action: "none", Actual: "enabled", Desired: "enabled"})
	} else {
		plan.add(servingPlanItem{ID: "service.enabled", Status: "change", Action: "enable", Actual: "disabled", Desired: "enabled"})
	}
	managedChange := plan.hasManagedChange()
	if !state.Available {
		plan.add(servingPlanItem{ID: "service.runtime", Status: "unknown", Action: "verify_on_apply", Actual: "systemd state unavailable", Desired: "active with planned state"})
	} else if !state.Active {
		plan.add(servingPlanItem{ID: "service.runtime", Status: "change", Action: "start", Actual: "inactive", Desired: "active"})
	} else if managedChange {
		plan.add(servingPlanItem{ID: "service.runtime", Status: "change", Action: "restart", Actual: "active with drift", Desired: "active with planned state"})
	} else {
		plan.add(servingPlanItem{ID: "service.runtime", Status: "noop", Action: "none", Actual: "active", Desired: "active"})
	}

	plan.finalize()
	return plan, nil
}

func desiredServingConfig(stateRoot, releaseRoot, listen, publicURL string) servingruntime.Config {
	return servingruntime.Config{
		Schema: servingruntime.ConfigSchema, Listen: listen, PublicURL: strings.TrimSuffix(publicURL, "/"),
		TLSCert: filepath.Join(stateRoot, "tls", "serving.crt"), TLSKey: filepath.Join(stateRoot, "tls", "serving.key"),
		ReleaseRoot: releaseRoot, ReleasePublicKey: filepath.Join(stateRoot, "trust", "release.public.pem"),
		DesiredPublicKey: filepath.Join(stateRoot, "trust", "desired-state.public.pem"), ControlPublicKey: filepath.Join(stateRoot, "trust", "control.public.pem"),
		EnrollmentState: filepath.Join(stateRoot, "private", "enrollments.json"), DesiredStateDir: filepath.Join(stateRoot, "private", "desired"),
		StatusDir: filepath.Join(stateRoot, "private", "status"), LogDir: filepath.Join(stateRoot, "private", "logs"),
		AuditLog: filepath.Join(stateRoot, "private", "audit.jsonl"), BootstrapScript: filepath.Join(stateRoot, "bootstrap.sh"), MaxClockSkewSeconds: 300,
	}
}

func (plan *servingReconcilePlan) add(item servingPlanItem) {
	plan.Items = append(plan.Items, item)
}

func (plan *servingReconcilePlan) hasManagedChange() bool {
	for _, item := range plan.Items {
		if item.Status == "change" && item.ID != "service.runtime" {
			return true
		}
	}
	return false
}

func (plan *servingReconcilePlan) finalize() {
	sort.Slice(plan.Items, func(i, j int) bool { return plan.Items[i].ID < plan.Items[j].ID })
	for _, item := range plan.Items {
		switch item.Status {
		case "noop":
			plan.Summary.Noop++
		case "change":
			plan.Summary.Changes++
		case "unsafe":
			plan.Summary.Unsafe++
		case "unknown":
			plan.Summary.Unknown++
		}
	}
	plan.Changed = plan.Summary.Changes > 0
	plan.Unsafe = plan.Summary.Unsafe > 0
	plan.Complete = plan.Summary.Unknown == 0
	plan.Applicable = !plan.Unsafe
	switch {
	case plan.Unsafe:
		plan.State = "unsafe"
	case plan.Changed:
		plan.State = "changes"
	case !plan.Complete:
		plan.State = "incomplete"
	default:
		plan.State = "noop"
	}
}

func formatServingPlan(plan servingReconcilePlan) string {
	var output strings.Builder
	fmt.Fprintf(&output, "PLAN state=%s changed=%t unsafe=%t complete=%t\n", plan.State, plan.Changed, plan.Unsafe, plan.Complete)
	for _, item := range plan.Items {
		fmt.Fprintf(&output, "[%s] %s action=%s", strings.ToUpper(item.Status), item.ID, item.Action)
		if item.Path != "" {
			fmt.Fprintf(&output, " path=%s", item.Path)
		}
		fmt.Fprintf(&output, " actual=%s desired=%s", item.Actual, item.Desired)
		if item.Detail != "" {
			fmt.Fprintf(&output, " detail=%s", item.Detail)
		}
		output.WriteByte('\n')
	}
	fmt.Fprintf(&output, "Summary: noop=%d changes=%d unsafe=%d unknown=%d", plan.Summary.Noop, plan.Summary.Changes, plan.Summary.Unsafe, plan.Summary.Unknown)
	return output.String()
}

func planServingDirectory(id, path string, metadata servingPlanMetadata) servingPlanItem {
	state := inspectServingPlanPath(path, true)
	desired := servingPlanMetadataText(metadata)
	if state.Unsafe != "" {
		return servingPlanItem{ID: id, Status: "unsafe", Action: "manual_repair", Path: path, Actual: state.Unsafe, Desired: desired}
	}
	if state.Unknown != "" {
		return servingPlanItem{ID: id, Status: "unknown", Action: "verify_on_apply", Path: path, Actual: state.Unknown, Desired: desired}
	}
	if !state.Exists {
		return servingPlanItem{ID: id, Status: "change", Action: "create", Path: path, Actual: "missing", Desired: desired}
	}
	match, actual := servingPlanMetadataMatches(state.Info, metadata)
	if !match {
		return servingPlanItem{ID: id, Status: "change", Action: "repair_metadata", Path: path, Actual: actual, Desired: desired}
	}
	return servingPlanItem{ID: id, Status: "noop", Action: "none", Path: path, Actual: actual, Desired: desired}
}

func planServingFile(id, path string, expected []byte, metadata servingPlanMetadata, desired string) servingPlanItem {
	return planServingFileWithState(id, path, expected, metadata, desired, inspectServingPlanPath(path, false))
}

func planServingFileWithState(id, path string, expected []byte, metadata servingPlanMetadata, desired string, state servingPlanPath) servingPlanItem {
	if state.Unsafe != "" {
		return servingPlanItem{ID: id, Status: "unsafe", Action: "manual_repair", Path: path, Actual: state.Unsafe, Desired: desired}
	}
	if state.Unknown != "" {
		return servingPlanItem{ID: id, Status: "unknown", Action: "verify_on_apply", Path: path, Actual: state.Unknown, Desired: desired}
	}
	if !state.Exists {
		return servingPlanItem{ID: id, Status: "change", Action: "create", Path: path, Actual: "missing", Desired: desired}
	}
	if linked, ok := state.Info.Sys().(*syscall.Stat_t); !ok || linked.Nlink != 1 {
		return servingPlanItem{ID: id, Status: "unsafe", Action: "manual_repair", Path: path, Actual: "hard-linked or unverifiable regular file", Desired: desired}
	}
	data, err := readServingPlanFile(path, int64(len(expected))+1)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) {
			return servingPlanItem{ID: id, Status: "unknown", Action: "verify_on_apply", Path: path, Actual: "protected", Desired: desired, Detail: "content comparison requires serving-file read access"}
		}
		return servingPlanItem{ID: id, Status: "unsafe", Action: "manual_repair", Path: path, Actual: "unreadable regular file", Desired: desired}
	}
	metadataMatch, actual := servingPlanMetadataMatches(state.Info, metadata)
	if !bytes.Equal(data, expected) {
		return servingPlanItem{ID: id, Status: "change", Action: "update", Path: path, Actual: "content differs; " + actual, Desired: desired}
	}
	if !metadataMatch {
		return servingPlanItem{ID: id, Status: "change", Action: "repair_metadata", Path: path, Actual: actual, Desired: desired}
	}
	return servingPlanItem{ID: id, Status: "noop", Action: "none", Path: path, Actual: "content matches; " + actual, Desired: desired}
}

func planServingMetadataFile(id, path string, state servingPlanPath, metadata servingPlanMetadata, desired string) servingPlanItem {
	if state.Unsafe != "" {
		return servingPlanItem{ID: id, Status: "unsafe", Action: "manual_repair", Path: path, Actual: state.Unsafe, Desired: desired}
	}
	if state.Unknown != "" {
		return servingPlanItem{ID: id, Status: "unknown", Action: "verify_on_apply", Path: path, Actual: state.Unknown, Desired: desired}
	}
	if !state.Exists {
		return servingPlanItem{ID: id, Status: "change", Action: "create", Path: path, Actual: "missing", Desired: desired}
	}
	if linked, ok := state.Info.Sys().(*syscall.Stat_t); !ok || linked.Nlink != 1 {
		return servingPlanItem{ID: id, Status: "unsafe", Action: "manual_repair", Path: path, Actual: "hard-linked or unverifiable regular file", Desired: desired}
	}
	match, actual := servingPlanMetadataMatches(state.Info, metadata)
	if !match {
		return servingPlanItem{ID: id, Status: "change", Action: "repair_metadata", Path: path, Actual: actual, Desired: desired}
	}
	return servingPlanItem{ID: id, Status: "noop", Action: "none", Path: path, Actual: actual, Desired: desired}
}

func planServingDeferredFile(id, path, action, desired string) servingPlanItem {
	state := inspectServingPlanPath(path, false)
	if state.Unsafe != "" {
		return servingPlanItem{ID: id, Status: "unsafe", Action: "manual_repair", Path: path, Actual: state.Unsafe, Desired: desired}
	}
	if state.Unknown != "" {
		return servingPlanItem{ID: id, Status: "unknown", Action: "verify_on_apply", Path: path, Actual: state.Unknown, Desired: desired}
	}
	actual := "missing"
	if state.Exists {
		if linked, ok := state.Info.Sys().(*syscall.Stat_t); !ok || linked.Nlink != 1 {
			return servingPlanItem{ID: id, Status: "unsafe", Action: "manual_repair", Path: path, Actual: "hard-linked or unverifiable regular file", Desired: desired}
		}
		return servingPlanItem{ID: id, Status: "unknown", Action: "verify_on_apply", Path: path, Actual: "present; exact content depends on protected or pending prerequisite", Desired: desired}
	}
	return servingPlanItem{ID: id, Status: "change", Action: action, Path: path, Actual: actual, Desired: desired}
}

func planServingPublicKeySource(id, path, keyID string) servingPlanItem {
	state := inspectServingPlanPath(path, false)
	desired := "verified ed25519:" + keyID
	if state.Unsafe != "" {
		return servingPlanItem{ID: id, Status: "unsafe", Action: "choose_safe_source", Path: path, Actual: state.Unsafe, Desired: desired}
	}
	if state.Unknown != "" {
		return servingPlanItem{ID: id, Status: "unknown", Action: "verify_on_apply", Path: path, Actual: state.Unknown, Desired: desired}
	}
	if !state.Exists {
		return servingPlanItem{ID: id, Status: "unsafe", Action: "restore_source", Path: path, Actual: "missing", Desired: desired}
	}
	if linked, ok := state.Info.Sys().(*syscall.Stat_t); !ok || linked.Nlink != 1 {
		return servingPlanItem{ID: id, Status: "unsafe", Action: "choose_safe_source", Path: path, Actual: "hard-linked or unverifiable public key source", Desired: desired}
	}
	data, err := readServingPlanFile(path, 16<<10)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			return servingPlanItem{ID: id, Status: "unknown", Action: "verify_on_apply", Path: path, Actual: "protected", Desired: desired}
		}
		return servingPlanItem{ID: id, Status: "unsafe", Action: "restore_source", Path: path, Actual: "unreadable public key source", Desired: desired}
	}
	publicKey, err := signing.ParsePublicPEM(data)
	if err != nil {
		return servingPlanItem{ID: id, Status: "unsafe", Action: "restore_source", Path: path, Actual: "invalid public key source", Desired: desired}
	}
	actualKeyID, err := signing.KeyID(publicKey)
	if err != nil || actualKeyID != keyID {
		return servingPlanItem{ID: id, Status: "unsafe", Action: "restore_source", Path: path, Actual: "public key source changed during planning", Desired: desired}
	}
	return servingPlanItem{ID: id, Status: "noop", Action: "none", Path: path, Actual: desired, Desired: desired}
}

func planServingExecutable(plan *servingReconcilePlan, path string, rootUID int) bool {
	if path == "" || !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00 ") {
		plan.add(servingPlanItem{ID: "service.executable", Status: "unsafe", Action: "install_protected", Path: path, Actual: "invalid executable path", Desired: "absolute protected flow executable"})
		return false
	}
	state := inspectServingPlanPath(path, false)
	if state.Unsafe != "" {
		plan.add(servingPlanItem{ID: "service.executable", Status: "unsafe", Action: "install_protected", Path: path, Actual: state.Unsafe, Desired: "root-owned non-writable regular flow executable"})
		return false
	}
	if state.Unknown != "" {
		plan.add(servingPlanItem{ID: "service.executable", Status: "unknown", Action: "verify_on_apply", Path: path, Actual: state.Unknown, Desired: "root-owned non-writable regular flow executable"})
		return false
	}
	if !state.Exists {
		plan.add(servingPlanItem{ID: "service.executable", Status: "change", Action: "install_protected", Path: path, Actual: "missing", Desired: "root-owned non-writable regular flow executable"})
		return false
	}
	stat, ok := state.Info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		plan.add(servingPlanItem{ID: "service.executable", Status: "unsafe", Action: "install_protected", Path: path, Actual: "hard-linked or unverifiable regular file", Desired: "root-owned non-writable regular flow executable"})
		return false
	}
	actual := fmt.Sprintf("mode=%04o uid=%d", state.Info.Mode().Perm(), stat.Uid)
	if int(stat.Uid) != rootUID || state.Info.Mode().Perm()&0o022 != 0 {
		plan.add(servingPlanItem{ID: "service.executable", Status: "change", Action: "install_protected", Path: path, Actual: actual, Desired: "root-owned non-writable regular flow executable"})
		return false
	}
	plan.add(servingPlanItem{ID: "service.executable", Status: "noop", Action: "none", Path: path, Actual: actual, Desired: "root-owned non-writable regular flow executable"})
	return true
}

func inspectServingPlanPath(path string, directory bool) servingPlanPath {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Clean(path) == string(filepath.Separator) || strings.ContainsRune(path, '\x00') {
		return servingPlanPath{Unsafe: "non-canonical or unsafe absolute path"}
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return servingPlanPath{}
		}
		if err != nil {
			if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
				return servingPlanPath{Unknown: "protected; metadata requires serving-file access"}
			}
			return servingPlanPath{Unsafe: "path metadata is unreadable"}
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return servingPlanPath{Unsafe: "path contains a symbolic link"}
		}
		if index != len(parts)-1 && !info.IsDir() {
			return servingPlanPath{Unsafe: "path ancestor is not a directory"}
		}
		if index == len(parts)-1 {
			if directory && !info.IsDir() {
				return servingPlanPath{Unsafe: "existing target is not a directory"}
			}
			if !directory && !info.Mode().IsRegular() {
				return servingPlanPath{Unsafe: "existing target is not a regular file"}
			}
			return servingPlanPath{Exists: true, Info: info}
		}
	}
	return servingPlanPath{Unsafe: "invalid empty path"}
}

func servingPlanMetadataMatches(info os.FileInfo, metadata servingPlanMetadata) (bool, string) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Sprintf("mode=%04o owner=unknown", info.Mode().Perm())
	}
	actual := fmt.Sprintf("mode=%04o uid=%d gid=%d", info.Mode().Perm(), stat.Uid, stat.Gid)
	match := info.Mode().Perm() == metadata.Mode.Perm()
	if metadata.CheckUID {
		match = match && int(stat.Uid) == metadata.UID
	}
	if metadata.CheckGID {
		match = match && int(stat.Gid) == metadata.GID
	}
	return match, actual
}

func servingPlanMetadataText(metadata servingPlanMetadata) string {
	if metadata.CheckUID && metadata.CheckGID {
		return fmt.Sprintf("mode=%04o uid=%d gid=%d", metadata.Mode.Perm(), metadata.UID, metadata.GID)
	}
	if metadata.CheckUID {
		return fmt.Sprintf("mode=%04o uid=%d gid=dedicated service identity after account creation", metadata.Mode.Perm(), metadata.UID)
	}
	return fmt.Sprintf("mode=%04o owner=dedicated service identity after account creation", metadata.Mode.Perm())
}

func readServingPlanFile(path string, limit int64) ([]byte, error) {
	if limit < 1 {
		limit = 1
	}
	file, err := openServingPlanFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("unsafe or oversized serving plan file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return nil, errors.New("hard-linked or unverifiable serving plan file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("unsafe or oversized serving plan file")
	}
	return data, nil
}

func openServingPlanFile(path string) (*os.File, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Clean(path) == string(filepath.Separator) {
		return nil, errors.New("unsafe serving plan file path")
	}
	current, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for index, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if index != len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, openErr := syscall.Openat(current, part, flags, 0)
		closeErr := syscall.Close(current)
		if openErr != nil {
			return nil, openErr
		}
		if closeErr != nil {
			_ = syscall.Close(next)
			return nil, closeErr
		}
		current = next
	}
	return os.NewFile(uintptr(current), path), nil
}

func servingPlanTLSFingerprint(data []byte) (string, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("invalid TLS certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(certificate.Raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:]), nil
}

func validateServingPlanTLSPair(certPath, keyPath string) error {
	certData, err := readServingPlanFile(certPath, 1<<20)
	if err != nil {
		return err
	}
	keyData, err := readServingPlanFile(keyPath, 1<<20)
	if err != nil {
		return err
	}
	certBlock, certRest := pem.Decode(certData)
	keyBlock, keyRest := pem.Decode(keyData)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(certRest)) != 0 ||
		keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(keyRest)) != 0 {
		return errors.New("invalid TLS PEM")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	publicKey, publicOK := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || !publicOK || !privateKey.Public().(ed25519.PublicKey).Equal(publicKey) {
		return errors.New("TLS certificate/private key mismatch")
	}
	return nil
}

func validateServingPlanTLSHost(certPath, publicURL string) error {
	data, err := readServingPlanFile(certPath, 1<<20)
	if err != nil {
		return err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("invalid TLS certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(publicURL)
	if err != nil || parsed.Hostname() == "" {
		return errors.New("invalid public URL")
	}
	return certificate.VerifyHostname(parsed.Hostname())
}

func inspectServingPlanAccount(name string) (servingPlanAccount, bool, error) {
	account, err := user.Lookup(name)
	if errors.Is(err, user.UnknownUserError(name)) {
		return servingPlanAccount{}, false, nil
	}
	if err != nil {
		return servingPlanAccount{}, false, err
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil || uid <= 0 || uid >= 1000 || gid <= 0 || account.Username != name || account.HomeDir != "/nonexistent" {
		return servingPlanAccount{}, true, errors.New("invalid dedicated serving identity")
	}
	lookup := exec.Command("/usr/bin/getent", "passwd", name)
	lookup.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	passwdOutput, lookupErr := lookup.Output()
	passwdFields := strings.Split(strings.TrimSpace(string(passwdOutput)), ":")
	if lookupErr != nil || len(passwdFields) != 7 || passwdFields[0] != name || passwdFields[2] != account.Uid || passwdFields[3] != account.Gid ||
		passwdFields[5] != "/nonexistent" || passwdFields[6] != "/usr/sbin/nologin" && passwdFields[6] != "/sbin/nologin" && passwdFields[6] != "/bin/false" {
		return servingPlanAccount{}, true, errors.New("invalid dedicated serving identity")
	}
	groups, groupsErr := account.GroupIds()
	if groupsErr != nil || len(groups) != 1 || groups[0] != account.Gid {
		return servingPlanAccount{}, true, errors.New("serving identity has supplementary groups")
	}
	status := exec.Command("/usr/bin/passwd", "--status", name)
	status.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	statusOutput, statusErr := status.Output()
	statusFields := strings.Fields(string(statusOutput))
	if statusErr != nil && os.Geteuid() != 0 {
		return servingPlanAccount{UID: uid, GID: gid}, true, os.ErrPermission
	}
	if statusErr != nil || len(statusFields) < 2 || statusFields[0] != name || statusFields[1] != "L" {
		return servingPlanAccount{}, true, errors.New("serving identity password is not locked")
	}
	return servingPlanAccount{UID: uid, GID: gid}, true, nil
}

func inspectServingPlanServiceState(name string) servingPlanServiceState {
	enabled, enabledAvailable := readSystemctlPredicate("is-enabled", name)
	active, activeAvailable := readSystemctlPredicate("is-active", name)
	loaded, fragmentPath, needsReload, definitionAvailable := inspectSystemdUnitDefinition(name)
	return servingPlanServiceState{
		Available: enabledAvailable && activeAvailable && definitionAvailable,
		Enabled:   enabled, Active: active, Loaded: loaded, FragmentPath: fragmentPath, NeedsReload: needsReload,
	}
}

func inspectSystemdUnitDefinition(name string) (bool, string, bool, bool) {
	command := exec.Command("/usr/bin/systemctl", "show", "--property=LoadState", "--property=FragmentPath", "--property=NeedDaemonReload", name)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	output, err := command.Output()
	if err != nil || len(output) > 64<<10 {
		return false, "", false, false
	}
	properties := make(map[string]string, 3)
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return false, "", false, false
		}
		properties[key] = value
	}
	loadState, loadOK := properties["LoadState"]
	fragmentPath, fragmentOK := properties["FragmentPath"]
	needReload, reloadOK := properties["NeedDaemonReload"]
	if !loadOK || !fragmentOK || !reloadOK || needReload != "yes" && needReload != "no" || strings.ContainsAny(fragmentPath, "\r\n\x00") {
		return false, "", false, false
	}
	if loadState != "loaded" {
		return false, "", needReload == "yes", true
	}
	if !filepath.IsAbs(fragmentPath) || filepath.Clean(fragmentPath) != fragmentPath {
		return false, "", false, false
	}
	return true, fragmentPath, needReload == "yes", true
}

func readSystemctlPredicate(predicate, name string) (bool, bool) {
	command := exec.Command("/usr/bin/systemctl", "--quiet", predicate, name)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	err := command.Run()
	if err == nil {
		return true, true
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return false, true
	}
	return false, false
}
