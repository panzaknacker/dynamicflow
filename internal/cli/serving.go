package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"dynamicflow/internal/release"
	"dynamicflow/internal/servingruntime"
	"dynamicflow/internal/signing"
	"dynamicflow/internal/tlsutil"
)

const (
	servingServiceName          = "dynamicflow-serving.service"
	defaultServingServiceUser   = "dynamicflow-serving"
	localServingReferenceSchema = 2
)

type localServingReference struct {
	Schema                 int    `json:"schema"`
	ConfigPath             string `json:"config_path"`
	StateRoot              string `json:"state_root"`
	ReleaseRoot            string `json:"release_root,omitempty"`
	ReleasePublicKeySource string `json:"release_public_key_source,omitempty"`
	DesiredPublicKeySource string `json:"desired_public_key_source,omitempty"`
	ControlPublicKeySource string `json:"control_public_key_source,omitempty"`
	ServiceUser            string `json:"service_user,omitempty"`
	PublicURL              string `json:"public_url"`
	Listen                 string `json:"listen"`
	Fingerprint            string `json:"tls_fingerprint"`
}

func commandStart(ctx *commandContext, args []string) int {
	if len(args) == 0 || args[0] != "serving" {
		return usage(ctx, "usage: flow start serving [--plan] [options]")
	}
	flags := flag.NewFlagSet("start serving", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	plan := flags.Bool("plan", false, "show reconciliation without mutation")
	listen := flags.String("listen", "", "listen address")
	publicURL := flags.String("public-url", "", "public HTTPS origin")
	stateRoot := flags.String("state-root", "", "absolute serving state root")
	releaseRoot := flags.String("release-root", "", "absolute verified release root")
	releaseKey := flags.String("release-public-key", "", "release public key PEM")
	desiredKey := flags.String("desired-public-key", "", "desired-state public key PEM")
	controlKey := flags.String("control-public-key", "", "control public key PEM")
	serviceUser := flags.String("service-user", "", "dedicated system account")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return usage(ctx, "usage: flow start serving [--plan] --public-url https://HOST:PORT [--listen HOST:PORT] [--state-root ABS] [--release-root ABS] [--release-public-key ABS --desired-public-key ABS --control-public-key ABS]")
	}
	existing, referenceErr := loadLocalServingReference(ctx)
	if referenceErr != nil && !errors.Is(referenceErr, os.ErrNotExist) {
		return ctx.out.fail("config", "local serving reference is invalid", "Repair or remove only the specific .flow serving reference after preserving its trust paths.", exitConfig)
	}
	if err := applyLocalServingReferenceDefaults(ctx, existing, stateRoot, listen, publicURL, releaseRoot, releaseKey, desiredKey, controlKey, serviceUser); err != nil {
		return ctx.out.fail("config", err.Error(), "Initialize local operator state and provide absolute public trust paths.", exitConfig)
	}
	if err := validateServingInputs(*stateRoot, *releaseRoot, *publicURL, *listen, *releaseKey, *desiredKey, *controlKey, *serviceUser); err != nil {
		return ctx.out.fail("config", err.Error(), "Provide absolute paths, a valid HTTPS origin and three distinct public keys.", exitConfig)
	}
	releasePublic, desiredPublic, controlPublic, current, err := servingPreflight(*releaseRoot, *releaseKey, *desiredKey, *controlKey)
	if err != nil {
		return ctx.out.fail("preflight", err.Error(), "Publish a verified release and provide the three public trust keys.", exitVerify)
	}
	configPath := filepath.Join(*stateRoot, "config.json")
	if *plan {
		return commandServingPlan(ctx, servingPlanInput{
			StateRoot: *stateRoot, ReleaseRoot: *releaseRoot, Listen: *listen, PublicURL: *publicURL,
			ReleaseKeySource: *releaseKey, DesiredKeySource: *desiredKey, ControlKeySource: *controlKey,
			ServiceUser: *serviceUser, ReleasePublic: releasePublic, DesiredPublic: desiredPublic,
			ControlPublic: controlPublic, Current: current, ExistingReference: existing,
			ReferenceExists: referenceErr == nil,
		}, defaultServingPlanEnvironment())
	}
	if os.Geteuid() != 0 {
		return ctx.out.fail("permission", "serving reconciliation must run as root", "Re-run this explicit command with sudo; --plan never needs root.", exitAuth)
	}
	executable, err := os.Executable()
	if err != nil {
		return ctx.out.fail("service", err.Error(), "Install flow at a stable absolute path.", exitConfig)
	}
	executable, err = filepath.Abs(executable)
	if err != nil || !safeServingUnitPath(executable) {
		return ctx.out.fail("service", "flow executable path is not safe for a systemd unit", "Install flow under /usr/local/bin and retry.", exitConfig)
	}
	if err := requireRootExecutable(executable); err != nil {
		return ctx.out.fail("service", err.Error(), "Install flow root-owned and non-writable at /usr/local/bin/flow.", exitConfig)
	}
	reconcilePlan, err := buildServingReconcilePlan(ctx, servingPlanInput{
		StateRoot: *stateRoot, ReleaseRoot: *releaseRoot, Listen: *listen, PublicURL: *publicURL,
		ReleaseKeySource: *releaseKey, DesiredKeySource: *desiredKey, ControlKeySource: *controlKey,
		ServiceUser: *serviceUser, ReleasePublic: releasePublic, DesiredPublic: desiredPublic,
		ControlPublic: controlPublic, Current: current, ExistingReference: existing,
		ReferenceExists: referenceErr == nil,
	}, defaultServingPlanEnvironment())
	if err != nil {
		return ctx.out.fail("plan", err.Error(), "Repair the verified release or public trust inputs and retry.", exitVerify)
	}
	if reconcilePlan.Unsafe {
		return ctx.out.failData("start.serving", reconcilePlan, "unsafe_state", "serving contains an unsafe existing path or identity", "Repair only the listed unsafe resource; no changes were made.", exitConfig)
	}
	if err := audit(ctx, "serving.start", "started", map[string]any{"state_root": *stateRoot, "release_set": current.Manifest.SetID}); err != nil {
		return ctx.out.fail("audit_unavailable", "local audit event could not be committed; serving reconciliation was not started", "Repair the private operator audit log and retry.", exitFailure)
	}
	if servingReconcilePlanIsNoop(reconcilePlan) {
		config := desiredServingConfig(*stateRoot, *releaseRoot, *listen, *publicURL)
		if err := waitForServingHealth(config, current.Manifest.SetID, reconcilePlan.ReleaseKeyID, reconcilePlan.DesiredKeyID, reconcilePlan.ControlKeyID, 30*time.Second); err != nil {
			_ = audit(ctx, "serving.start", "failure", map[string]any{"release_set": current.Manifest.SetID, "changed": false, "error_code": "service_health"})
			return ctx.out.fail("service_health", err.Error(), "Run flow logs serving; no service or filesystem mutation was attempted.", exitRemote)
		}
		if err := audit(ctx, "serving.start", "success", map[string]any{"release_set": current.Manifest.SetID, "changed": false}); err != nil {
			return ctx.out.fail("audit_unavailable", "serving health was verified, but the successful no-op audit event could not be committed", "Repair the private operator audit log; no service or serving-state mutation was attempted.", exitFailure)
		}
		return ctx.out.success("start.serving", map[string]any{
			"changed": false, "active": true, "public_url": config.PublicURL, "listen": config.Listen,
			"service_user": *serviceUser, "tls_fingerprint": reconcilePlan.TLSFingerprint,
			"release_set": current.Manifest.SetID, "config": configPath,
		}, fmt.Sprintf("Serving is already converged at %s\nTLS pin: %s\nRelease: %s", config.PublicURL, reconcilePlan.TLSFingerprint, current.Manifest.SetID))
	}
	ctx.out.phase("account", "running", *serviceUser)
	uid, gid, err := ensureServiceAccount(*serviceUser)
	if err != nil {
		return ctx.out.fail("account", err.Error(), "Create or repair the dedicated serving account.", exitFailure)
	}
	if err := stopServingBeforeRootReconcile(); err != nil {
		return ctx.out.fail("service", err.Error(), "Stop and inspect the existing serving unit before root reconciliation.", exitFailure)
	}
	ctx.out.phase("state", "running", *stateRoot)
	if err := ensureServingDirectories(*stateRoot, *releaseRoot, uid, gid); err != nil {
		return ctx.out.fail("state", err.Error(), "Remove unsafe symlinks or repair serving directory permissions.", exitConfig)
	}
	trustDir := filepath.Join(*stateRoot, "trust")
	releasePublicPath := filepath.Join(trustDir, "release.public.pem")
	desiredPublicPath := filepath.Join(trustDir, "desired-state.public.pem")
	controlPublicPath := filepath.Join(trustDir, "control.public.pem")
	changed := false
	for _, item := range []struct {
		path string
		key  ed25519.PublicKey
	}{{releasePublicPath, releasePublic}, {desiredPublicPath, desiredPublic}, {controlPublicPath, controlPublic}} {
		pemData, marshalErr := signing.MarshalPublicPEM(item.key)
		if marshalErr != nil {
			return ctx.out.fail("trust", marshalErr.Error(), "Repair the public trust key.", exitVerify)
		}
		itemChanged, writeErr := writeAtomicIfChanged(item.path, pemData, 0o644, 0, gid)
		if writeErr != nil {
			return ctx.out.fail("trust", writeErr.Error(), "Repair serving trust directory permissions.", exitConfig)
		}
		changed = changed || itemChanged
	}
	tlsCert := filepath.Join(*stateRoot, "tls", "serving.crt")
	tlsKey := filepath.Join(*stateRoot, "tls", "serving.key")
	if certExists, keyExists := fileExists(tlsCert), fileExists(tlsKey); certExists != keyExists {
		return ctx.out.fail("tls", "serving TLS identity is incomplete", "Restore the matching pair; flow will not replace it silently.", exitVerify)
	} else if !certExists {
		parsed, _ := url.Parse(*publicURL)
		host := parsed.Hostname()
		if _, err := tlsutil.GenerateSelfSigned(tlsCert, tlsKey, []string{host}, time.Now().UTC()); err != nil {
			return ctx.out.fail("tls", err.Error(), "Repair serving TLS directory permissions.", exitFailure)
		}
		changed = true
	} else if err := tlsutil.ValidatePair(tlsCert, tlsKey); err != nil {
		return ctx.out.fail("tls", err.Error(), "Restore the existing serving TLS identity; it was not replaced.", exitVerify)
	}
	fingerprint, err := tlsutil.Fingerprint(tlsCert)
	if err != nil {
		return ctx.out.fail("tls", err.Error(), "Repair the serving certificate.", exitVerify)
	}
	bootstrap, err := buildBootstrap(*publicURL, current, tlsCert, releasePublicPath, desiredPublicPath)
	if err != nil {
		return ctx.out.fail("bootstrap", err.Error(), "Ensure the active release contains flow for amd64 and arm64.", exitVerify)
	}
	bootstrapPath := filepath.Join(*stateRoot, "bootstrap.sh")
	itemChanged, err := writeAtomicIfChanged(bootstrapPath, bootstrap, 0o640, 0, gid)
	if err != nil {
		return ctx.out.fail("bootstrap", err.Error(), "Repair serving state permissions.", exitConfig)
	}
	changed = changed || itemChanged
	config := desiredServingConfig(*stateRoot, *releaseRoot, *listen, *publicURL)
	if err := servingruntime.Validate(config); err != nil {
		return ctx.out.fail("config", err.Error(), "Correct the serving configuration.", exitConfig)
	}
	configData, _ := signing.CanonicalJSON(config)
	itemChanged, err = writeAtomicIfChanged(configPath, configData, 0o640, 0, gid)
	if err != nil {
		return ctx.out.fail("config", err.Error(), "Repair serving state permissions.", exitConfig)
	}
	changed = changed || itemChanged
	if err := secureServingOwnership(*stateRoot, *releaseRoot, uid, gid); err != nil {
		return ctx.out.fail("permissions", err.Error(), "Remove unsafe entries and repair serving ownership.", exitConfig)
	}
	unit := servingUnit(executable, configPath, *stateRoot, *releaseRoot, *serviceUser, strconv.Itoa(gid))
	unitChanged, err := writeAtomicIfChanged(filepath.Join("/etc/systemd/system", servingServiceName), []byte(unit), 0o644, 0, 0)
	if err != nil {
		return ctx.out.fail("service", err.Error(), "Repair /etc/systemd/system permissions.", exitFailure)
	}
	changed = changed || unitChanged
	if err := runSystemctl("daemon-reload"); err != nil {
		return ctx.out.fail("service", err.Error(), "Inspect systemd and the serving unit.", exitFailure)
	}
	if err := runSystemctl("enable", "--now", servingServiceName); err != nil {
		return ctx.out.fail("service", err.Error(), "Run flow logs serving and inspect systemd.", exitFailure)
	}
	if changed {
		if err := runSystemctl("restart", servingServiceName); err != nil {
			return ctx.out.fail("service", err.Error(), "Run flow logs serving and inspect systemd.", exitFailure)
		}
	}
	releaseKeyID, _ := signing.KeyID(releasePublic)
	desiredKeyID, _ := signing.KeyID(desiredPublic)
	controlKeyID, _ := signing.KeyID(controlPublic)
	if err := waitForServingHealth(config, current.Manifest.SetID, releaseKeyID, desiredKeyID, controlKeyID, 30*time.Second); err != nil {
		return ctx.out.fail("service_health", err.Error(), "Run flow logs serving; verify certificate SAN/validity, trust-key bindings and the active release.", exitRemote)
	}
	reference := localServingReference{
		Schema: localServingReferenceSchema, ConfigPath: configPath, StateRoot: *stateRoot, ReleaseRoot: *releaseRoot,
		ReleasePublicKeySource: *releaseKey, DesiredPublicKeySource: *desiredKey, ControlPublicKeySource: *controlKey,
		ServiceUser: *serviceUser, PublicURL: config.PublicURL, Listen: config.Listen, Fingerprint: fingerprint,
	}
	if err := ctx.store.WriteJSON("serving/local.json", reference); err != nil {
		return ctx.out.fail("state", err.Error(), "Serving is running, but the local reference could not be stored.", exitPartial)
	}
	audit(ctx, "serving.start", "success", map[string]any{"release_set": current.Manifest.SetID, "changed": changed})
	return ctx.out.success("start.serving", map[string]any{
		"changed": changed, "active": true, "public_url": config.PublicURL, "listen": config.Listen,
		"service_user": *serviceUser, "tls_fingerprint": fingerprint, "release_set": current.Manifest.SetID, "config": configPath,
	}, fmt.Sprintf("Serving is active at %s\nTLS pin: %s\nRelease: %s", config.PublicURL, fingerprint, current.Manifest.SetID))
}

func servingReconcilePlanIsNoop(plan servingReconcilePlan) bool {
	return plan.State == "noop" && !plan.Changed && !plan.Unsafe && plan.Complete && plan.Applicable
}

func commandStatus(ctx *commandContext, args []string) int {
	if len(args) != 1 || args[0] != "serving" {
		return usage(ctx, "usage: flow status serving")
	}
	reference, err := loadLocalServingReference(ctx)
	if err != nil {
		return ctx.out.fail("config", err.Error(), "Run flow start serving --plan, then reconcile serving.", exitConfig)
	}
	config, err := servingruntime.Load(reference.ConfigPath)
	if err != nil {
		return ctx.out.fail("config", err.Error(), "Repair serving configuration and permissions.", exitConfig)
	}
	active := exec.Command("systemctl", "is-active", "--quiet", servingServiceName).Run() == nil
	releasePublic, err := signing.LoadPublicFile(config.ReleasePublicKey)
	var setID string
	if err == nil {
		if signed, _, currentErr := release.Current(config.ReleaseRoot, releasePublic); currentErr == nil {
			setID = signed.Manifest.SetID
		} else {
			err = currentErr
		}
	}
	health := "unreachable"
	if active {
		health = localServingHealth(config)
	}
	data := map[string]any{"active": active, "health": health, "public_url": config.PublicURL, "listen": config.Listen, "release_set": setID, "tls_fingerprint": reference.Fingerprint, "config": reference.ConfigPath}
	if !active || err != nil || health != "ok" {
		return ctx.out.failData("status.serving", data, "serving_unhealthy", fmt.Sprintf("active=%t health=%s release_error=%v", active, health, err), "Run flow logs serving; the previous verified release remains on disk.", exitRemote)
	}
	return ctx.out.success("status.serving", data, fmt.Sprintf("Serving: active (%s)\nRelease: %s", health, setID))
}

func commandLogs(ctx *commandContext, args []string) int {
	if len(args) == 0 || args[0] != "serving" {
		return usage(ctx, "usage: flow logs serving [--lines N]")
	}
	flags := flag.NewFlagSet("logs serving", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	lines := flags.Int("lines", 200, "number of journal lines")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *lines < 1 || *lines > 10000 {
		return usage(ctx, "usage: flow logs serving [--lines 1..10000]")
	}
	command := exec.Command("journalctl", "--unit", servingServiceName, "--no-pager", "--output", "short-iso", "-n", strconv.Itoa(*lines))
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return ctx.out.fail("logs", strings.TrimSpace(stderr.String()), "Run as an account allowed to read the system journal.", exitRemote)
	}
	content := strings.TrimRight(stdout.String(), "\n")
	if ctx.out.json {
		return ctx.out.success("logs.serving", map[string]any{"service": servingServiceName, "lines": strings.Split(content, "\n")}, "")
	}
	fmt.Fprintln(ctx.out.stdout, content)
	return exitOK
}

func commandServeRaw(args []string, stdout, stderr io.Writer, jsonOutput bool) int {
	emit := &emitter{json: jsonOutput, stdout: stdout, stderr: stderr, command: "serve"}
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	config := flags.String("config", "", "absolute serving config")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !filepath.IsAbs(*config) {
		return emit.fail("usage", "usage: flow serve --config ABSOLUTE-PATH", "This is an internal systemd entry point.", exitUsage)
	}
	operation, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := servingruntime.Run(operation, *config); err != nil {
		return emit.fail("serving", err.Error(), "Inspect the sanitized system journal and serving audit log.", exitFailure)
	}
	return exitOK
}

func validateServingInputs(stateRoot, releaseRoot, publicURL, listen, releaseKey, desiredKey, controlKey, serviceUser string) error {
	if !safeServingUnitPath(stateRoot) || !safeServingUnitPath(releaseRoot) {
		return errors.New("serving state and release roots must be canonical absolute non-root paths without whitespace or control characters")
	}
	if !validServingReleaseRoot(stateRoot, releaseRoot) {
		return errors.New("release root must be a separate subtree of the serving state root outside private, trust and tls")
	}
	parsed, err := url.Parse(publicURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return errors.New("--public-url must be one HTTPS origin")
	}
	if _, _, err := net.SplitHostPort(listen); err != nil {
		return errors.New("invalid --listen address")
	}
	for _, path := range []string{releaseKey, desiredKey, controlKey} {
		if !filepath.IsAbs(path) {
			return errors.New("public key paths must be absolute")
		}
	}
	if !validServiceUser(serviceUser) {
		return errors.New("invalid dedicated service user")
	}
	return nil
}

func servingPreflight(releaseRoot, releaseKey, desiredKey, controlKey string) (ed25519.PublicKey, ed25519.PublicKey, ed25519.PublicKey, release.SignedManifest, error) {
	releasePublic, err := signing.LoadPublicFile(releaseKey)
	if err != nil {
		return nil, nil, nil, release.SignedManifest{}, err
	}
	desiredPublic, err := signing.LoadPublicFile(desiredKey)
	if err != nil {
		return nil, nil, nil, release.SignedManifest{}, err
	}
	controlPublic, err := signing.LoadPublicFile(controlKey)
	if err != nil {
		return nil, nil, nil, release.SignedManifest{}, err
	}
	if releasePublic.Equal(desiredPublic) || releasePublic.Equal(controlPublic) || desiredPublic.Equal(controlPublic) {
		return nil, nil, nil, release.SignedManifest{}, errors.New("release, desired-state and control keys must be distinct")
	}
	current, _, err := release.Current(releaseRoot, releasePublic)
	return releasePublic, desiredPublic, controlPublic, current, err
}

func ensureServiceAccount(name string) (int, int, error) {
	if name != defaultServingServiceUser {
		return 0, 0, errors.New("serving requires the dedicated dynamicflow-serving account")
	}
	account, err := user.Lookup(name)
	if errors.Is(err, user.UnknownUserError(name)) {
		command := exec.Command("/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", name)
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
		if output, runErr := command.CombinedOutput(); runErr != nil {
			return 0, 0, fmt.Errorf("create service account: %w: %s", runErr, strings.TrimSpace(string(output)))
		}
		account, err = user.Lookup(name)
	}
	if err != nil {
		return 0, 0, err
	}
	if account.Username != name || account.HomeDir != "/nonexistent" {
		return 0, 0, errors.New("existing serving account is not a dedicated locked system identity")
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil || uid <= 0 || uid >= 1000 || gid <= 0 {
		return 0, 0, errors.New("serving account must have a non-root system UID and GID")
	}
	lookup := exec.Command("/usr/bin/getent", "passwd", name)
	lookup.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	passwdOutput, err := lookup.Output()
	passwdFields := strings.Split(strings.TrimSpace(string(passwdOutput)), ":")
	if err != nil || len(passwdFields) != 7 || passwdFields[0] != name ||
		passwdFields[2] != account.Uid || passwdFields[3] != account.Gid ||
		passwdFields[5] != "/nonexistent" ||
		(passwdFields[6] != "/usr/sbin/nologin" && passwdFields[6] != "/sbin/nologin" && passwdFields[6] != "/bin/false") {
		return 0, 0, errors.New("serving account passwd record is not a dedicated nologin identity")
	}
	groups, err := account.GroupIds()
	if err != nil || len(groups) != 1 || groups[0] != account.Gid {
		return 0, 0, errors.New("serving account must have no supplementary groups")
	}
	status := exec.Command("/usr/bin/passwd", "--status", name)
	status.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	output, err := status.Output()
	fields := strings.Fields(string(output))
	if err != nil || len(fields) < 2 || fields[0] != name || fields[1] != "L" {
		return 0, 0, errors.New("serving account password is not locked")
	}
	return uid, gid, nil
}

func ensureServingDirectories(stateRoot, releaseRoot string, uid, gid int) error {
	for _, item := range []struct {
		path string
		mode os.FileMode
		uid  int
		gid  int
	}{
		{stateRoot, 0o751, 0, gid}, {releaseRoot, 0o755, uid, gid},
		{filepath.Join(releaseRoot, "sets"), 0o755, uid, gid},
		{filepath.Join(releaseRoot, ".imports"), 0o700, uid, gid},
		{filepath.Join(stateRoot, "trust"), 0o755, 0, gid},
		{filepath.Join(stateRoot, "tls"), 0o750, 0, gid},
		{filepath.Join(stateRoot, "private"), 0o700, uid, gid},
		{filepath.Join(stateRoot, "private", "desired"), 0o700, uid, gid},
		{filepath.Join(stateRoot, "private", "status"), 0o700, uid, gid},
		{filepath.Join(stateRoot, "private", "logs"), 0o700, uid, gid},
	} {
		if err := ensureAbsoluteDirectoryOwned(item.path, item.mode, item.uid, item.gid); err != nil {
			return err
		}
	}
	return nil
}

func ensureAbsoluteDirectoryOwned(path string, mode os.FileMode, uid, gid int) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) == "/" {
		return errors.New("unsafe directory path")
	}
	parentFD, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	for index, part := range parts {
		childFD, openErr := syscall.Openat(parentFD, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if errors.Is(openErr, syscall.ENOENT) {
			createMode := uint32(0o755)
			if index == len(parts)-1 {
				createMode = uint32(mode.Perm())
			}
			if mkdirErr := syscall.Mkdirat(parentFD, part, createMode); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				syscall.Close(parentFD)
				return mkdirErr
			}
			childFD, openErr = syscall.Openat(parentFD, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			syscall.Close(parentFD)
			return errors.New("directory path contains a symlink or non-directory")
		}
		if closeErr := syscall.Close(parentFD); closeErr != nil {
			syscall.Close(childFD)
			return closeErr
		}
		parentFD = childFD
	}
	defer syscall.Close(parentFD)
	if err := syscall.Fchown(parentFD, uid, gid); err != nil {
		return err
	}
	if err := syscall.Fchmod(parentFD, uint32(mode.Perm())); err != nil {
		return err
	}
	var metadata syscall.Stat_t
	if err := syscall.Fstat(parentFD, &metadata); err != nil ||
		metadata.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		int(metadata.Uid) != uid || int(metadata.Gid) != gid ||
		os.FileMode(metadata.Mode).Perm() != mode.Perm() {
		return errors.New("directory metadata could not be verified")
	}
	return nil
}

func buildBootstrap(publicURL string, manifest release.SignedManifest, certPath, releaseKeyPath, desiredKeyPath string) ([]byte, error) {
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	releasePublic, err := os.ReadFile(releaseKeyPath)
	if err != nil {
		return nil, err
	}
	desiredPublic, err := os.ReadFile(desiredKeyPath)
	if err != nil {
		return nil, err
	}
	tlsPin, err := tlsutil.Fingerprint(certPath)
	if err != nil {
		return nil, err
	}
	return buildBootstrapFromData(publicURL, manifest, tlsPin, cert, releasePublic, desiredPublic)
}

// buildBootstrapFromData keeps planning and reconciliation on the exact same
// deterministic bootstrap representation. Its inputs contain public trust
// material plus the serving transport certificate; no signing or TLS private
// key is accepted.
func buildBootstrapFromData(publicURL string, manifest release.SignedManifest, tlsPin string, cert, releasePublic, desiredPublic []byte) ([]byte, error) {
	components := map[string]release.Component{}
	for _, component := range manifest.Manifest.Components {
		if component.Name == "flow" && (component.Target == "linux-amd64" || component.Target == "linux-arm64") {
			components[component.Target] = component
		}
	}
	amd64, amdOK := components["linux-amd64"]
	arm64, armOK := components["linux-arm64"]
	if !amdOK || !armOK {
		return nil, errors.New("active release lacks flow bootstrap targets")
	}
	var script strings.Builder
	script.WriteString("#!/bin/sh\nset -eu\numask 077\n")
	script.WriteString("admin_user=${SUDO_USER:-}\n")
	script.WriteString("case \"$admin_user\" in ''|root|malwarelab) printf '%s\\n' 'Run bootstrap through sudo from the intended unprivileged administrative account.' >&2; exit 3;; esac\n")
	script.WriteString("case \"$admin_user\" in [a-z_]*) ;; *) printf '%s\\n' 'Unsafe SUDO_USER for --admin-user.' >&2; exit 3;; esac\n")
	script.WriteString("case \"$admin_user\" in *[!a-z0-9_-]*) printf '%s\\n' 'Unsafe SUDO_USER for --admin-user.' >&2; exit 3;; esac\n")
	script.WriteString("[ \"${#admin_user}\" -le 31 ] || { printf '%s\\n' 'Unsafe SUDO_USER for --admin-user.' >&2; exit 3; }\n")
	script.WriteString("tmp=$(mktemp -d)\ncleanup() { rm -rf -- \"$tmp\"; }\ntrap cleanup EXIT HUP INT TERM\n")
	writeHereDoc(&script, "$tmp/serving-ca.pem", cert)
	writeHereDoc(&script, "$tmp/release.public.pem", releasePublic)
	writeHereDoc(&script, "$tmp/desired-state.public.pem", desiredPublic)
	script.WriteString("case \"$(uname -m)\" in\n")
	script.WriteString("  x86_64|amd64) artifact=" + shellQuote(amd64.Artifact) + "; expected=" + shellQuote(strings.TrimPrefix(amd64.Digest, "sha256:")) + ";;\n")
	script.WriteString("  aarch64|arm64) artifact=" + shellQuote(arm64.Artifact) + "; expected=" + shellQuote(strings.TrimPrefix(arm64.Digest, "sha256:")) + ";;\n")
	script.WriteString("  *) printf '%s\\n' 'Unsupported architecture' >&2; exit 3;;\nesac\n")
	script.WriteString("curl --fail --silent --show-error --proto '=https' --tlsv1.2 --cacert \"$tmp/serving-ca.pem\" " + shellQuote(strings.TrimSuffix(publicURL, "/")+"/v1/releases/current/artifacts/") + "\"$artifact\" -o \"$tmp/flow\"\n")
	script.WriteString("actual=$(sha256sum \"$tmp/flow\" | awk '{print $1}')\n[ \"$actual\" = \"$expected\" ] || { printf '%s\\n' 'flow artifact digest mismatch' >&2; exit 5; }\n")
	script.WriteString("install -d -m 0700 /etc/dynamicflow/trust\ninstall -m 0644 \"$tmp/serving-ca.pem\" /etc/dynamicflow/trust/serving-ca.pem\ninstall -m 0644 \"$tmp/release.public.pem\" /etc/dynamicflow/trust/release.public.pem\ninstall -m 0644 \"$tmp/desired-state.public.pem\" /etc/dynamicflow/trust/desired-state.public.pem\n")
	script.WriteString("install -m 0755 \"$tmp/flow\" /usr/local/bin/flow.new\nmv -f /usr/local/bin/flow.new /usr/local/bin/flow\n")
	script.WriteString("cleanup\ntrap - EXIT HUP INT TERM\n")
	enrollmentCommand := "/usr/local/bin/flow instance-runtime enroll --server " + shellQuote(strings.TrimSuffix(publicURL, "/")) +
		" --tls-ca /etc/dynamicflow/trust/serving-ca.pem --tls-pin " + shellQuote(tlsPin) +
		" --release-public-key /etc/dynamicflow/trust/release.public.pem --desired-public-key /etc/dynamicflow/trust/desired-state.public.pem --admin-user \"$admin_user\""
	script.WriteString("run_enrollment() {\n  exec " + enrollmentCommand + "\n}\n")
	// A curl-to-shell quickstart inherits curl's exhausted pipe as stdin even
	// when it still has a controlling console. Explicitly reopen that console
	// so all four enrollment fields, especially the secret, remain hidden and
	// interactive. Truly headless bootstraps retain the bounded stdin path.
	script.WriteString("if ( : </dev/tty ) 2>/dev/null; then\n  run_enrollment </dev/tty\nfi\n")
	script.WriteString("run_enrollment\n")
	return []byte(script.String()), nil
}

func writeHereDoc(builder *strings.Builder, target string, content []byte) {
	builder.WriteString("cat >\"")
	builder.WriteString(target)
	builder.WriteString("\" <<'DYNAMICFLOW_EOF'\n")
	builder.Write(content)
	if len(content) == 0 || content[len(content)-1] != '\n' {
		builder.WriteByte('\n')
	}
	builder.WriteString("DYNAMICFLOW_EOF\n")
}

func servingUnit(executable, configPath, stateRoot, releaseRoot, serviceUser, serviceGroup string) string {
	return `[Unit]
Description=Dynamicflow internal serving and enrollment service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=` + serviceUser + `
Group=` + serviceGroup + `
ExecStart=` + executable + ` serve --config ` + configPath + `
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadOnlyPaths=` + stateRoot + `
ReadWritePaths=` + filepath.Join(stateRoot, "private") + `
ReadWritePaths=` + releaseRoot + `

[Install]
WantedBy=multi-user.target
`
}

func writeAtomicIfChanged(path string, data []byte, mode os.FileMode, uid, gid int) (bool, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return false, errors.New("unsafe write target")
	}
	directoryFD, err := openAbsoluteDirectoryNoFollow(filepath.Dir(path))
	if err != nil {
		return false, err
	}
	defer syscall.Close(directoryFD)
	name := filepath.Base(path)

	existingFD, openErr := syscall.Openat(directoryFD, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if openErr == nil {
		existing := os.NewFile(uintptr(existingFD), path)
		if existing == nil {
			syscall.Close(existingFD)
			return false, errors.New("existing target could not be opened")
		}
		var metadata syscall.Stat_t
		if err := syscall.Fstat(existingFD, &metadata); err != nil || metadata.Mode&syscall.S_IFMT != syscall.S_IFREG || metadata.Nlink != 1 {
			existing.Close()
			return false, errors.New("existing target is not a single-link regular file")
		}
		existingData, readErr := io.ReadAll(io.LimitReader(existing, int64(len(data))+1))
		if readErr != nil {
			existing.Close()
			return false, readErr
		}
		if bytes.Equal(existingData, data) {
			metadataMatches := os.FileMode(metadata.Mode).Perm() == mode.Perm() && int(metadata.Uid) == uid && int(metadata.Gid) == gid
			if metadataMatches {
				return false, existing.Close()
			}
			if err := syscall.Fchown(existingFD, uid, gid); err != nil {
				existing.Close()
				return false, err
			}
			if err := syscall.Fchmod(existingFD, uint32(mode.Perm())); err != nil {
				existing.Close()
				return false, err
			}
			if err := existing.Sync(); err != nil {
				existing.Close()
				return false, err
			}
			if err := existing.Close(); err != nil {
				return false, err
			}
			return true, syscall.Fsync(directoryFD)
		}
		if err := existing.Close(); err != nil {
			return false, err
		}
	} else if !errors.Is(openErr, syscall.ENOENT) {
		return false, errors.New("existing target is unsafe or unreadable")
	}

	random := make([]byte, 12)
	temporaryFD := -1
	var temporaryName string
	for attempt := 0; attempt < 32; attempt++ {
		if _, err := rand.Read(random); err != nil {
			return false, err
		}
		temporaryName = ".flow-write-" + hex.EncodeToString(random)
		temporaryFD, err = syscall.Openat(directoryFD, temporaryName, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, uint32(mode.Perm()))
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EEXIST) {
			return false, err
		}
	}
	if temporaryFD < 0 || temporaryName == "" {
		return false, errors.New("could not allocate atomic serving write")
	}
	committed := false
	defer func() {
		if !committed {
			_ = syscall.Unlinkat(directoryFD, temporaryName)
		}
	}()
	temporary := os.NewFile(uintptr(temporaryFD), filepath.Join(filepath.Dir(path), temporaryName))
	if temporary == nil {
		syscall.Close(temporaryFD)
		return false, errors.New("temporary target could not be opened")
	}
	if err := syscall.Fchown(temporaryFD, uid, gid); err != nil {
		temporary.Close()
		return false, err
	}
	if err := syscall.Fchmod(temporaryFD, uint32(mode.Perm())); err != nil {
		temporary.Close()
		return false, err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := syscall.Renameat(directoryFD, temporaryName, directoryFD, name); err != nil {
		return false, err
	}
	committed = true
	return true, syscall.Fsync(directoryFD)
}

func requireRootExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("flow service executable must be a protected regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("flow service executable must be owned by root")
	}
	return nil
}

func secureServingOwnership(stateRoot, releaseRoot string, uid, gid int) error {
	// Never recursively repair the service-writable private tree as root.
	// Only the fixed directories are opened with O_NOFOLLOW and changed via
	// their descriptors; runtime-created files are validated by serving when
	// it opens them.
	for _, directory := range []string{
		filepath.Join(stateRoot, "private"),
		filepath.Join(stateRoot, "private", "desired"),
		filepath.Join(stateRoot, "private", "status"),
		filepath.Join(stateRoot, "private", "logs"),
	} {
		if err := ensureAbsoluteDirectoryOwned(directory, 0o700, uid, gid); err != nil {
			return err
		}
	}
	if !validServingReleaseRoot(stateRoot, releaseRoot) {
		return errors.New("release root overlaps protected serving state")
	}
	if err := ensureAbsoluteDirectoryOwned(stateRoot, 0o751, 0, gid); err != nil {
		return err
	}
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{releaseRoot, 0o755},
		{filepath.Join(releaseRoot, "sets"), 0o755},
		{filepath.Join(releaseRoot, ".imports"), 0o700},
	} {
		if err := ensureAbsoluteDirectoryOwned(directory.path, directory.mode, uid, gid); err != nil {
			return err
		}
	}
	if err := ensureReleasePublishLockOwned(releaseRoot, uid, gid); err != nil {
		return err
	}
	if err := ensureAbsoluteDirectoryOwned(filepath.Join(stateRoot, "trust"), 0o755, 0, gid); err != nil {
		return err
	}
	if err := ensureAbsoluteDirectoryOwned(filepath.Join(stateRoot, "tls"), 0o750, 0, gid); err != nil {
		return err
	}
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Join(stateRoot, "trust", "release.public.pem"), 0o644},
		{filepath.Join(stateRoot, "trust", "desired-state.public.pem"), 0o644},
		{filepath.Join(stateRoot, "trust", "control.public.pem"), 0o644},
		{filepath.Join(stateRoot, "tls", "serving.crt"), 0o644},
		{filepath.Join(stateRoot, "tls", "serving.key"), 0o640},
		{filepath.Join(stateRoot, "bootstrap.sh"), 0o640},
		{filepath.Join(stateRoot, "config.json"), 0o640},
	} {
		if err := secureServingControlFile(item.path, item.mode, gid); err != nil {
			return err
		}
	}
	return nil
}

func secureServingControlFile(path string, mode os.FileMode, gid int) error {
	directoryFD, err := openAbsoluteDirectoryNoFollow(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer syscall.Close(directoryFD)
	fd, err := syscall.Openat(directoryFD, filepath.Base(path), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("serving control file is missing or unsafe")
	}
	defer syscall.Close(fd)
	var metadata syscall.Stat_t
	if err := syscall.Fstat(fd, &metadata); err != nil || metadata.Mode&syscall.S_IFMT != syscall.S_IFREG || metadata.Nlink != 1 {
		return errors.New("serving control file is not a single-link regular file")
	}
	if err := syscall.Fchown(fd, 0, gid); err != nil {
		return err
	}
	if err := syscall.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return err
	}
	if err := syscall.Fstat(fd, &metadata); err != nil || metadata.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		metadata.Nlink != 1 || metadata.Uid != 0 || int(metadata.Gid) != gid || os.FileMode(metadata.Mode).Perm() != mode.Perm() {
		return errors.New("serving control file metadata could not be verified")
	}
	return nil
}

func ensureReleasePublishLockOwned(releaseRoot string, uid, gid int) error {
	rootFD, err := openAbsoluteDirectoryNoFollow(releaseRoot)
	if err != nil {
		return err
	}
	defer syscall.Close(rootFD)
	fd, err := syscall.Openat(rootFD, ".publish.lock", syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var metadata syscall.Stat_t
	if err := syscall.Fstat(fd, &metadata); err != nil || metadata.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		metadata.Nlink != 1 || metadata.Size != 0 ||
		(metadata.Uid != 0 && int(metadata.Uid) != uid) ||
		(metadata.Gid != 0 && int(metadata.Gid) != gid) {
		return errors.New("release publish lock is unsafe")
	}
	if err := syscall.Fchown(fd, uid, gid); err != nil {
		return err
	}
	if err := syscall.Fchmod(fd, 0o600); err != nil {
		return err
	}
	if err := syscall.Fstat(fd, &metadata); err != nil || metadata.Mode&0o777 != 0o600 ||
		int(metadata.Uid) != uid || int(metadata.Gid) != gid || metadata.Size != 0 || metadata.Nlink != 1 {
		return errors.New("release publish lock metadata could not be verified")
	}
	return syscall.Fsync(rootFD)
}

func openAbsoluteDirectoryNoFollow(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return -1, errors.New("unsafe directory path")
	}
	fd, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			syscall.Close(fd)
			return -1, errors.New("unsafe directory path")
		}
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		syscall.Close(fd)
		if openErr != nil {
			return -1, errors.New("directory path contains a symlink or non-directory")
		}
		fd = next
	}
	return fd, nil
}

func runSystemctl(arguments ...string) error {
	command := exec.Command("/usr/bin/systemctl", arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func stopServingBeforeRootReconcile() error {
	unitPath := filepath.Join("/etc/systemd/system", servingServiceName)
	info, err := os.Lstat(unitPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 || !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return errors.New("existing serving systemd unit is unsafe")
	}
	return runSystemctl("stop", servingServiceName)
}

func applyLocalServingReferenceDefaults(
	ctx *commandContext,
	existing localServingReference,
	stateRoot, listen, publicURL, releaseRoot, releaseKey, desiredKey, controlKey, serviceUser *string,
) error {
	if ctx == nil || ctx.store == nil || stateRoot == nil || listen == nil || publicURL == nil || releaseRoot == nil ||
		releaseKey == nil || desiredKey == nil || controlKey == nil || serviceUser == nil {
		return errors.New("invalid serving default context")
	}
	if *stateRoot == "" {
		*stateRoot = existing.StateRoot
		if *stateRoot == "" {
			*stateRoot = "/var/lib/dynamicflow-serving"
		}
	}
	if *listen == "" {
		*listen = existing.Listen
		if *listen == "" {
			*listen = "0.0.0.0:8443"
		}
	}
	if *publicURL == "" {
		*publicURL = existing.PublicURL
	}
	if *serviceUser == "" {
		*serviceUser = existing.ServiceUser
		if *serviceUser == "" {
			*serviceUser = defaultServingServiceUser
		}
	}
	if *releaseRoot == "" {
		*releaseRoot = existing.ReleaseRoot
		if *releaseRoot == "" {
			*releaseRoot = filepath.Join(*stateRoot, "releases")
		}
	}
	for _, key := range []struct {
		value    *string
		existing string
		name     string
	}{
		{releaseKey, existing.ReleasePublicKeySource, "release"},
		{desiredKey, existing.DesiredPublicKeySource, "desired-state"},
		{controlKey, existing.ControlPublicKeySource, "control"},
	} {
		if *key.value != "" {
			continue
		}
		*key.value = key.existing
		if *key.value == "" {
			path, err := ctx.store.Path(filepath.Join("keys", "signing", key.name+".public.pem"))
			if err != nil {
				return err
			}
			*key.value = path
		}
	}
	return nil
}

func loadLocalServingReference(ctx *commandContext) (localServingReference, error) {
	var reference localServingReference
	if err := ctx.store.ReadJSON("serving/local.json", &reference); err != nil {
		return reference, err
	}
	if reference.Schema == 1 {
		if !safeServingReferencePath(reference.StateRoot) ||
			reference.ConfigPath != filepath.Join(reference.StateRoot, "config.json") {
			return localServingReference{}, errors.New("invalid legacy local serving reference")
		}
		config, err := servingruntime.Load(reference.ConfigPath)
		if err != nil || config.PublicURL != strings.TrimSuffix(reference.PublicURL, "/") || config.Listen != reference.Listen {
			return localServingReference{}, errors.New("legacy local serving reference does not match its root-created config")
		}
		fingerprint, err := tlsutil.Fingerprint(config.TLSCert)
		if err != nil || fingerprint != reference.Fingerprint {
			return localServingReference{}, errors.New("legacy local serving reference TLS identity does not match")
		}
		reference.Schema = localServingReferenceSchema
		reference.ReleaseRoot = config.ReleaseRoot
		reference.ReleasePublicKeySource = config.ReleasePublicKey
		reference.DesiredPublicKeySource = config.DesiredPublicKey
		reference.ControlPublicKeySource = config.ControlPublicKey
		reference.ServiceUser = defaultServingServiceUser
	}
	if err := validateLocalServingReference(reference); err != nil {
		return localServingReference{}, err
	}
	return reference, nil
}

func validateLocalServingReference(reference localServingReference) error {
	if reference.Schema != localServingReferenceSchema || !safeServingUnitPath(reference.StateRoot) ||
		reference.ConfigPath != filepath.Join(reference.StateRoot, "config.json") ||
		!safeServingUnitPath(reference.ReleaseRoot) || !validServingReleaseRoot(reference.StateRoot, reference.ReleaseRoot) ||
		!validServiceUser(reference.ServiceUser) {
		return errors.New("invalid local serving reference paths")
	}
	for _, path := range []string{
		reference.ReleasePublicKeySource, reference.DesiredPublicKeySource, reference.ControlPublicKeySource,
	} {
		if !safeServingReferencePath(path) {
			return errors.New("invalid local serving public-key source")
		}
	}
	parsed, err := url.Parse(reference.PublicURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return errors.New("invalid local serving public URL")
	}
	host, port, err := net.SplitHostPort(reference.Listen)
	if err != nil || host == "" || port == "" || strings.ContainsAny(host, "\r\n\x00") {
		return errors.New("invalid local serving listen address")
	}
	if !strings.HasPrefix(reference.Fingerprint, "SHA256:") {
		return errors.New("invalid local serving TLS fingerprint")
	}
	digest, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(reference.Fingerprint, "SHA256:"))
	if err != nil || len(digest) != 32 || reference.Fingerprint != "SHA256:"+base64.RawStdEncoding.EncodeToString(digest) {
		return errors.New("invalid local serving TLS fingerprint")
	}
	return nil
}

func safeServingReferencePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator) &&
		!strings.ContainsRune(path, '\x00')
}

func safeServingUnitPath(path string) bool {
	return safeServingReferencePath(path) && !strings.ContainsFunc(path, func(character rune) bool {
		return unicode.IsSpace(character) || unicode.IsControl(character)
	})
}

func localServingHealth(config servingruntime.Config) string {
	health, status, err := queryLocalServingHealth(config)
	if err != nil {
		return "unreachable"
	}
	if status == http.StatusOK && health.Status == "ok" {
		return "ok"
	}
	return "degraded"
}

type servingHealthResponse struct {
	Status       string `json:"status"`
	ReleaseSet   string `json:"release_set"`
	ReleaseKeyID string `json:"release_key_id"`
	DesiredKeyID string `json:"desired_key_id"`
	ControlKeyID string `json:"control_key_id"`
}

func queryLocalServingHealth(config servingruntime.Config) (servingHealthResponse, int, error) {
	var health servingHealthResponse
	certificate, err := os.ReadFile(config.TLSCert)
	if err != nil {
		return health, 0, err
	}
	pool, err := tlsCertPool(certificate)
	if err != nil {
		return health, 0, err
	}
	client := &http.Client{
		Timeout:       5 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: pool, Proxy: nil},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("serving health redirected") },
	}
	response, err := client.Get(strings.TrimSuffix(config.PublicURL, "/") + "/v1/health")
	if err != nil {
		return health, 0, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return health, response.StatusCode, errors.New("invalid serving health response")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&health); err != nil {
		return health, response.StatusCode, errors.New("invalid serving health response")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return health, response.StatusCode, errors.New("invalid serving health response")
	}
	return health, response.StatusCode, nil
}

func waitForServingHealth(config servingruntime.Config, releaseSet, releaseKeyID, desiredKeyID, controlKeyID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		health, status, err := queryLocalServingHealth(config)
		if err == nil && status == http.StatusOK && health.Status == "ok" &&
			health.ReleaseSet == releaseSet && health.ReleaseKeyID == releaseKeyID &&
			health.DesiredKeyID == desiredKeyID && health.ControlKeyID == controlKeyID {
			return nil
		}
		if err != nil {
			last = err
		} else {
			last = errors.New("serving health bindings do not match the reconciled state")
		}
		if !time.Now().Before(deadline) {
			return last
		}
		time.Sleep(time.Second)
	}
}

func tlsCertPool(certificate []byte) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certificate) {
		return nil, errors.New("invalid serving CA certificate")
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, nil
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func validServingReleaseRoot(stateRoot, releaseRoot string) bool {
	relative, err := filepath.Rel(filepath.Clean(stateRoot), filepath.Clean(releaseRoot))
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	first, _, _ := strings.Cut(relative, string(filepath.Separator))
	switch first {
	case "private", "trust", "tls", "config.json", "bootstrap.sh":
		return false
	default:
		return first != ""
	}
}

func validServiceUser(value string) bool {
	return value == defaultServingServiceUser
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
