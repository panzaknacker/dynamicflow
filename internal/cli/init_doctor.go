package cli

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"dynamicflow/internal/profiles"
	"dynamicflow/internal/signing"
)

type operatorConfig struct {
	Schema    int       `json:"schema"`
	CreatedAt time.Time `json:"created_at"`
	Version   string    `json:"flow_version"`
}

type initResult struct {
	Home            string   `json:"home"`
	Created         []string `json:"created"`
	Existing        []string `json:"existing"`
	ReleaseSignerID string   `json:"release_signer_id"`
	DesiredSignerID string   `json:"desired_state_signer_id"`
	ControlKeyID    string   `json:"control_key_id"`
	AuditLog        string   `json:"audit_log"`
}

func commandInit(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "init")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return usage(ctx, "usage: flow init")
	}
	ctx.out.phase("state", "running", ctx.home)
	for _, directory := range []string{"keys/signing", "keys/operator", "keys/instance", "instances", "releases", "serving", "logs"} {
		if _, err := ctx.store.EnsureDir(directory); err != nil {
			return ctx.out.fail("config", err.Error(), "Fix FLOW_HOME ownership and mode, then retry.", exitConfig)
		}
	}
	result := initResult{Home: ctx.home}
	keys := []struct {
		name       string
		privateRel string
		publicRel  string
		identifier *string
	}{
		{"release signing key", "keys/signing/release.private.pem", "keys/signing/release.public.pem", &result.ReleaseSignerID},
		{"desired-state signing key", "keys/signing/desired-state.private.pem", "keys/signing/desired-state.public.pem", &result.DesiredSignerID},
		{"serving control key", "keys/signing/control.private.pem", "keys/signing/control.public.pem", &result.ControlKeyID},
	}
	for _, key := range keys {
		privatePath, _ := ctx.store.Path(key.privateRel)
		publicPath, _ := ctx.store.Path(key.publicRel)
		privateExists := exists(privatePath)
		publicExists := exists(publicPath)
		if privateExists != publicExists {
			return ctx.out.fail("config", key.name+" is incomplete", "Restore the missing matching key; flow will not replace trust roots.", exitConfig)
		}
		if !privateExists {
			if _, err := signing.GenerateFiles(privatePath, publicPath); err != nil {
				return ctx.out.fail("config", err.Error(), "Check the private state directory and retry.", exitConfig)
			}
			result.Created = append(result.Created, key.name)
		} else {
			result.Existing = append(result.Existing, key.name)
		}
		privateKey, publicKey, err := loadSigningPair(privatePath, publicPath)
		if err != nil {
			return ctx.out.fail("verify", key.name+": "+err.Error(), "Restore the correct signing key pair.", exitVerify)
		}
		_ = privateKey
		*key.identifier, _ = signing.KeyID(publicKey)
	}
	if err := distinctSigningRoots(result.ReleaseSignerID, result.DesiredSignerID, result.ControlKeyID); err != nil {
		return ctx.out.fail("verify", err.Error(), "Restore three independent signing roots; flow will not replace existing trust roots.", exitVerify)
	}
	configPath, _ := ctx.store.Path("operator.json")
	if !exists(configPath) {
		if err := ctx.store.WriteJSON("operator.json", operatorConfig{Schema: 1, CreatedAt: time.Now().UTC(), Version: Version}); err != nil {
			return ctx.out.fail("config", err.Error(), "Check the private state directory.", exitConfig)
		}
		result.Created = append(result.Created, "operator configuration")
	} else {
		var config operatorConfig
		if err := ctx.store.ReadJSON("operator.json", &config); err != nil || config.Schema != 1 {
			return ctx.out.fail("config", "operator configuration is invalid", "Recover it rather than overwriting signing state.", exitConfig)
		}
		result.Existing = append(result.Existing, "operator configuration")
	}
	result.AuditLog, _ = ctx.store.Path("logs/audit.jsonl")
	audit(ctx, "init", "success", map[string]any{"created": result.Created})
	ctx.out.phase("state", "complete", "private operator state is ready")
	return ctx.out.success("init", result, fmt.Sprintf("Dynamicflow initialized at %s\nRelease signer: %s\nDesired-state signer: %s\nServing control key: %s\nAudit log: %s", result.Home, result.ReleaseSignerID, result.DesiredSignerID, result.ControlKeyID, result.AuditLog))
}

func distinctSigningRoots(releaseID, desiredID, controlID string) error {
	if releaseID == "" || desiredID == "" || controlID == "" {
		return errors.New("cannot verify signing-root separation until all three key pairs are valid")
	}
	if releaseID == desiredID {
		return errors.New("release and desired-state signing roles share one Ed25519 root")
	}
	if releaseID == controlID {
		return errors.New("release and serving-control signing roles share one Ed25519 root")
	}
	if desiredID == controlID {
		return errors.New("desired-state and serving-control signing roles share one Ed25519 root")
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func loadSigningPair(privatePath, publicPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privateKey, err := signing.LoadPrivateFile(privatePath)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := signing.LoadPublicFile(publicPath)
	if err != nil {
		return nil, nil, err
	}
	derived := privateKey.Public().(ed25519.PublicKey)
	if !derived.Equal(publicKey) {
		return nil, nil, errors.New("private/public keys do not match")
	}
	return privateKey, publicKey, nil
}

type doctorCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func commandDoctor(ctx *commandContext, args []string) int {
	flags := newCommandFlagSet(ctx, "doctor")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return usage(ctx, "usage: flow doctor")
	}
	if status, handled := doctorSystem(ctx); handled {
		return status
	}
	checks := []doctorCheck{}
	add := func(name string, err error, success string) {
		check := doctorCheck{Name: name, OK: err == nil, Detail: success}
		if err != nil {
			check.Detail = err.Error()
		}
		checks = append(checks, check)
	}
	for _, tool := range []string{"ssh", "ssh-keygen"} {
		path, err := exec.LookPath(tool)
		add("tool:"+tool, err, path)
	}
	signingIDs := make(map[string]string, 3)
	for _, pair := range []struct {
		role       string
		privateRel string
		publicRel  string
	}{
		{"release", "keys/signing/release.private.pem", "keys/signing/release.public.pem"},
		{"desired-state", "keys/signing/desired-state.private.pem", "keys/signing/desired-state.public.pem"},
		{"serving-control", "keys/signing/control.private.pem", "keys/signing/control.public.pem"},
	} {
		privatePath, _ := ctx.store.Path(pair.privateRel)
		publicPath, _ := ctx.store.Path(pair.publicRel)
		_, publicKey, err := loadSigningPair(privatePath, publicPath)
		if err == nil {
			signingIDs[pair.role], err = signing.KeyID(publicKey)
		}
		add("signing:"+filepath.Base(publicPath), err, "valid matching Ed25519 pair")
	}
	separationErr := distinctSigningRoots(signingIDs["release"], signingIDs["desired-state"], signingIDs["serving-control"])
	add("signing:key-separation", separationErr, "release, desired-state, and serving-control use independent Ed25519 roots")
	if ctx.profiles == "" {
		add("profiles", errors.New("profile directory not found; set --source-root or FLOW_PROFILES_DIR"), "")
	} else {
		registry, err := profiles.LoadDir(ctx.profiles)
		if err == nil {
			_, err = registry.Resolve("pbp")
		}
		add("profiles", err, ctx.profiles)
	}
	allOK := true
	for _, check := range checks {
		if !check.OK {
			allOK = false
		}
		if !ctx.out.json {
			state := "OK"
			if !check.OK {
				state = "FAIL"
			}
			fmt.Fprintf(ctx.out.stdout, "%-5s %-34s %s\n", state, check.Name, check.Detail)
		}
	}
	data := map[string]any{"healthy": allOK, "checks": checks, "home": ctx.home}
	if !allOK {
		if ctx.out.json {
			return ctx.out.failData("doctor", data, "doctor_failed", "one or more checks failed", "Run flow init, then resolve every failed check.", exitConfig)
		}
		return exitConfig
	}
	audit(ctx, "doctor", "success", nil)
	if ctx.out.json {
		return ctx.out.success("doctor", data, "")
	}
	return exitOK
}
