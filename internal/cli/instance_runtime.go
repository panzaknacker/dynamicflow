package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"dynamicflow/internal/applyplan"
	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/instanceclient"
	"dynamicflow/internal/instanceunit"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/profiles"
	"dynamicflow/internal/reconcile"
	"dynamicflow/internal/release"
	"dynamicflow/internal/serving"
	"dynamicflow/internal/signing"
	"dynamicflow/internal/sshkeys"
	"dynamicflow/internal/targetapply"
	"dynamicflow/internal/vncsecret"
)

const (
	instanceRuntimeConfigSchema = 2
	instanceRuntimeConfigPath   = "runtime-config.json"
	instanceRuntimeReportPath   = "reports/log-sequences.json"
	instanceRuntimeReportLock   = "reports/log-sequences.lock"
	defaultInstanceRuntimeRoot  = "/var/lib/dynamicflow/instance"
	defaultRuntimeTimeout       = 20 * time.Second
	maxRuntimeCABytes           = 64 << 10
	maxRuntimePublicKeyBytes    = 8 << 10
	maxRuntimeSSHHostKeyBytes   = 4 << 10
)

var (
	errRuntimeInput         = errors.New("invalid target runtime input")
	errRuntimeConfiguration = errors.New("invalid target runtime configuration")
	errRuntimeConflict      = errors.New("target runtime binding conflict")
	errRuntimeReporting     = errors.New("target runtime reporting incomplete")
	errRuntimeFailClosed    = errors.New("target runtime fail-closed action failed")
	errRuntimeApply         = errors.New("target profile apply failed")
	errRuntimeService       = errors.New("target reconcile service installation failed")
	errRuntimeHelp          = errors.New("target runtime help requested")
	runtimeIdentifierRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	runtimeAdminUserRE      = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
	runtimeKeyIDRE          = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type instanceRuntimeClient interface {
	Enroll(context.Context, string, io.Reader) (instanceclient.EnrollmentResult, error)
	FetchDesired(context.Context) (instanceclient.EnrollmentResult, error)
	DownloadArtifact(context.Context, release.SignedManifest, release.Component, io.Writer) error
	ReportStatus(context.Context, serving.StatusReport) error
	ReportLogs(context.Context, serving.LogBatch) error
	State() instanceclient.State
	IdentityKeyID() string
	Close() error
}

type instanceRuntimeInput interface {
	ReadField(prompt string, hidden bool, maximum int) ([]byte, error)
	Finalize() error
	Close() error
}

type instanceRuntimeDependencies struct {
	goos           string
	goarch         string
	uid            func() int
	euid           func() int
	now            func() time.Time
	stdin          io.Reader
	sshConnection  func() string
	openInput      func(io.Reader) (instanceRuntimeInput, error)
	readPublicFile func(string, int64) ([]byte, error)
	readSSHHostKey func() (string, error)
	validateAdmin  func(string) error
	newClient      func(instanceclient.Config) (instanceRuntimeClient, error)
	loadCheckpoint func(string) (applyplan.Checkpoint, string, error)
	runApply       func(context.Context, targetapply.Config) (targetapply.Result, error)
	revoke         func(context.Context, string, string, string) error
	installTimer   func(string) (bool, error)
	bridgePBPLogs  func(context.Context, instanceRuntimeConfig, instanceRuntimeClient, func() time.Time) error
	vncReveal      func() ([]byte, error)
	vncRotate      func() ([]byte, error)
}

type instanceRuntimeEnrollOptions struct {
	server         string
	tlsCA          string
	tlsPin         string
	releasePublic  string
	desiredPublic  string
	adminUser      string
	stateRoot      string
	requestTimeout time.Duration
}

// instanceRuntimeConfig contains public trust and binding data only. in
// particular, enrollment ID and secret have no fields and cannot be encoded.
type instanceRuntimeConfig struct {
	Schema           int    `json:"schema"`
	Server           string `json:"server"`
	TLSCA            string `json:"tls_ca"`
	TLSPin           string `json:"tls_pin"`
	ReleasePublicKey string `json:"release_public_key"`
	DesiredPublicKey string `json:"desired_public_key"`
	StateRoot        string `json:"state_root"`
	Instance         string `json:"instance"`
	Profile          string `json:"profile"`
	AdminUser        string `json:"admin_user"`
	IdentityKeyID    string `json:"identity_key_id"`
	RequestTimeout   string `json:"request_timeout"`
	EnrolledAt       int64  `json:"enrolled_at"`
}

type instanceRuntimeApplyOutcome struct {
	Applied           bool
	HandoffRequired   bool
	Revoked           bool
	FailClosed        bool
	ReportingDegraded bool
	PlanID            string
	AppliedGeneration uint64
}

type instanceRuntimeTrust struct {
	releasePublic ed25519.PublicKey
	desiredPublic ed25519.PublicKey
}

type instanceRuntimeLogSequenceState struct {
	Schema int               `json:"schema"`
	Last   map[string]uint64 `json:"last"`
}

type instanceRuntimeEnrollmentInput struct {
	instance     string
	profile      string
	enrollmentID []byte
}

type deferredRuntimeSecret struct {
	input    instanceRuntimeInput
	data     []byte
	offset   int
	loaded   bool
	finished bool
	err      error
}

func commandInstanceRuntimeRaw(arguments []string, stdout, stderr io.Writer, jsonOutput bool) int {
	command := requestedCommandID(append([]string{"instance-runtime"}, arguments...))
	out := &emitter{json: jsonOutput, stdout: stdout, stderr: stderr, command: command}
	return runInstanceRuntime(arguments, out, defaultInstanceRuntimeDependencies())
}

func defaultInstanceRuntimeDependencies() instanceRuntimeDependencies {
	return instanceRuntimeDependencies{
		goos: runtime.GOOS, goarch: runtime.GOARCH,
		uid: os.Getuid, euid: os.Geteuid, now: time.Now,
		stdin: os.Stdin, sshConnection: func() string { return os.Getenv("SSH_CONNECTION") },
		openInput:      openDefaultInstanceRuntimeInput,
		readPublicFile: readRootOwnedRuntimePublicFile,
		readSSHHostKey: readRuntimeSSHHostKey,
		validateAdmin:  targetapply.ValidateAdminUser,
		newClient: func(config instanceclient.Config) (instanceRuntimeClient, error) {
			return instanceclient.New(config)
		},
		loadCheckpoint: targetapply.LoadCheckpoint,
		runApply:       targetapply.Run,
		revoke:         targetapply.Revoke,
		installTimer:   instanceunit.Install,
		bridgePBPLogs:  reportPBPRuntimeLogs,
		vncReveal:      vncsecret.Reveal,
		vncRotate:      vncsecret.Rotate,
	}
}

func runInstanceRuntime(arguments []string, out *emitter, deps instanceRuntimeDependencies) int {
	if len(arguments) == 0 {
		return out.fail("usage", "instance-runtime requires enroll, reconcile, status, or secret", "Run flow instance-runtime --help.", exitUsage)
	}
	if isRuntimeHelp(arguments[0]) {
		fmt.Fprint(out.stdout, instanceRuntimeHelpText)
		return exitOK
	}
	switch arguments[0] {
	case "enroll":
		return commandInstanceRuntimeEnroll(arguments[1:], out, deps)
	case "reconcile":
		return commandInstanceRuntimeReconcile(arguments[1:], out, deps)
	case "status":
		return commandInstanceRuntimeStatus(arguments[1:], out, deps)
	case "secret":
		return commandInstanceRuntimeSecret(arguments[1:], out, deps)
	default:
		return out.fail("usage", "unknown instance-runtime command", "Run flow instance-runtime --help.", exitUsage)
	}
}

func commandInstanceRuntimeSecret(arguments []string, out *emitter, deps instanceRuntimeDependencies) int {
	// accept exactly the fixed argv emitted by flow instance secret. there are
	// no paths, usernames, units, credentials, or general commands to vary.
	if len(arguments) != 3 || (arguments[0] != "reveal" && arguments[0] != "rotate") || arguments[1] != "--secret" || arguments[2] != "vnc" {
		return out.fail("usage", "invalid fixed VNC credential operation", "Use flow instance secret reveal|rotate NAME --secret vnc from the operator machine.", exitUsage)
	}
	if out.json {
		return out.fail("usage", "--json is not valid for the internal VNC credential channel", "Use the operator-facing flow --json instance secret command.", exitUsage)
	}
	if status := validateRuntimePlatform(out, deps); status != exitOK {
		return status
	}
	operation := deps.vncReveal
	if arguments[0] == "rotate" {
		operation = deps.vncRotate
	}
	if operation == nil {
		return out.fail("config", "target VNC credential operation is unavailable", "Repair the installed flow target binary.", exitConfig)
	}
	value, err := operation()
	if err != nil {
		return out.fail("vnc_secret", "target VNC credential operation failed safely", "Inspect the fixed TigerVNC unit and root-only target state; no credential was logged.", exitFailure)
	}
	defer clearRuntimeBytes(value)
	if !validRuntimeVNCSecret(value) {
		return out.fail("vnc_secret", "target VNC credential result failed validation", "Repair the managed VNC credential state.", exitVerify)
	}
	// this raw, single-line stdout is the deliberate secret channel consumed by
	// the operator CLI. never route it through structured logs or error text.
	if _, err := fmt.Fprintf(out.stdout, "%s\n", value); err != nil {
		return exitFailure
	}
	return exitOK
}

func validRuntimeVNCSecret(value []byte) bool {
	if len(value) != 8 {
		return false
	}
	for _, item := range value {
		if item < '0' || item > '9' && item < 'A' || item > 'Z' && item < 'a' || item > 'z' {
			return false
		}
	}
	return true
}

func commandInstanceRuntimeEnroll(arguments []string, out *emitter, deps instanceRuntimeDependencies) int {
	options, err := parseInstanceRuntimeEnrollOptions(arguments)
	if errors.Is(err, errRuntimeHelp) {
		fmt.Fprint(out.stdout, instanceRuntimeHelpText)
		return exitOK
	}
	if err != nil {
		return out.fail("usage", err.Error(), "No instance binding or credential may be supplied as an argument.", exitUsage)
	}
	if status := validateRuntimePlatform(out, deps); status != exitOK {
		return status
	}
	if err := validateInstanceRuntimeAdmin(options.adminUser, deps); err != nil {
		return failInstanceRuntime(out, err)
	}
	// Install and enable the fixed pull-only timer before any enrollment
	// credential is opened or consumed. the service itself is guarded by the
	// atomically persisted runtime-config.json, so an interrupted enrollment is
	// inert while an interrupted apply is resumed after reboot or the next tick.
	if deps.installTimer == nil {
		return failInstanceRuntime(out, errRuntimeConfiguration)
	}
	if _, err := deps.installTimer(options.stateRoot); err != nil {
		return failInstanceRuntime(out, fmt.Errorf("%w: %v", errRuntimeService, err))
	}
	store, err := openInstanceRuntimeStore(options.stateRoot)
	if err != nil {
		return failInstanceRuntime(out, err)
	}
	existing, exists, err := readInstanceRuntimeConfig(store)
	if err != nil {
		return failInstanceRuntime(out, err)
	}
	if exists {
		if !existing.matchesPublicOptions(options) {
			return failInstanceRuntime(out, errRuntimeConflict)
		}
		client, err := newBoundInstanceRuntimeClient(existing, deps)
		if err != nil {
			return failInstanceRuntime(out, err)
		}
		defer client.Close()
		result, err := client.FetchDesired(context.Background())
		if err != nil {
			return failInstanceRuntime(out, err)
		}
		outcome, applyErr := applyInstanceRuntimeResult(context.Background(), existing, client, result, deps)
		return finishInstanceRuntimeApply(out, "instance-runtime.enroll", result, existing.StateRoot, true, false, outcome, applyErr)
	}

	input, err := deps.openInput(deps.stdin)
	if err != nil {
		return out.fail("input", "could not open /dev/tty or stdin", "Provide four bounded input lines as documented.", exitAuth)
	}
	defer input.Close()
	fields, err := readInstanceRuntimeEnrollmentInput(input)
	if err != nil {
		return out.fail("input", "instance enrollment input was missing or invalid", "Provide instance, profile, enrollment ID, then secret.", exitAuth)
	}
	defer fields.clear()

	binding := instanceRuntimeConfig{
		Schema: instanceRuntimeConfigSchema,
		Server: strings.TrimSuffix(options.server, "/"), TLSCA: options.tlsCA, TLSPin: options.tlsPin,
		ReleasePublicKey: options.releasePublic, DesiredPublicKey: options.desiredPublic,
		StateRoot: options.stateRoot, Instance: fields.instance, Profile: fields.profile, AdminUser: options.adminUser,
		RequestTimeout: options.requestTimeout.String(),
	}
	client, err := newBoundInstanceRuntimeClient(binding, deps)
	if err != nil {
		return failInstanceRuntime(out, err)
	}
	defer client.Close()
	secret := &deferredRuntimeSecret{input: input}
	defer secret.clear()
	result, enrollErr := client.Enroll(context.Background(), string(fields.enrollmentID), secret)
	recovered := false
	if enrollErr != nil && shouldRecoverInstanceEnrollment(enrollErr) {
		result, err = client.FetchDesired(context.Background())
		if err == nil {
			recovered = true
			enrollErr = nil
		} else if errors.Is(enrollErr, instanceclient.ErrEnrollmentOutcomeUnknown) {
			return out.fail(
				"enrollment_outcome_unknown",
				"serving may have consumed the enrollment; signed desired-state recovery did not complete",
				"Retry the same instance-runtime enroll command; the stable identity will be reused.",
				exitPartial,
			)
		}
	}
	if enrollErr != nil {
		return failInstanceRuntime(out, enrollErr)
	}
	binding.IdentityKeyID = client.IdentityKeyID()
	binding.EnrolledAt = deps.now().UTC().Unix()
	if err := persistInstanceRuntimeConfig(store, binding); err != nil {
		return out.fail(
			"state_partial", "enrollment succeeded but public runtime configuration was not committed",
			"Do not request a new enrollment; rerun this command to recover with the stable identity.", exitPartial,
		)
	}
	outcome, applyErr := applyInstanceRuntimeResult(context.Background(), binding, client, result, deps)
	return finishInstanceRuntimeApply(out, "instance-runtime.enroll", result, binding.StateRoot, recovered, false, outcome, applyErr)
}

func commandInstanceRuntimeReconcile(arguments []string, out *emitter, deps instanceRuntimeDependencies) int {
	stateRoot, err := parseInstanceRuntimeStateOptions("instance-runtime reconcile", arguments)
	if errors.Is(err, errRuntimeHelp) {
		fmt.Fprint(out.stdout, instanceRuntimeHelpText)
		return exitOK
	}
	if err != nil {
		return out.fail("usage", err.Error(), "Run flow instance-runtime --help.", exitUsage)
	}
	if status := validateRuntimePlatform(out, deps); status != exitOK {
		return status
	}
	config, client, err := loadConfiguredInstanceRuntime(stateRoot, deps)
	if err != nil {
		return failInstanceRuntime(out, err)
	}
	defer client.Close()
	result, err := client.FetchDesired(context.Background())
	if err != nil {
		return failInstanceRuntime(out, err)
	}
	if deps.bridgePBPLogs != nil && !result.Desired.State.Revoked {
		// local PBP diagnostics are best-effort telemetry. an unavailable or
		// unsafe source must never block desired-state reconciliation.
		_ = deps.bridgePBPLogs(context.Background(), config, client, deps.now)
	}
	outcome, applyErr := applyInstanceRuntimeResult(context.Background(), config, client, result, deps)
	return finishInstanceRuntimeApply(out, "instance-runtime.reconcile", result, config.StateRoot, true, false, outcome, applyErr)
}

func commandInstanceRuntimeStatus(arguments []string, out *emitter, deps instanceRuntimeDependencies) int {
	stateRoot, err := parseInstanceRuntimeStateOptions("instance-runtime status", arguments)
	if errors.Is(err, errRuntimeHelp) {
		fmt.Fprint(out.stdout, instanceRuntimeHelpText)
		return exitOK
	}
	if err != nil {
		return out.fail("usage", err.Error(), "Run flow instance-runtime --help.", exitUsage)
	}
	if status := validateRuntimePlatform(out, deps); status != exitOK {
		return status
	}
	config, client, err := loadConfiguredInstanceRuntime(stateRoot, deps)
	if err != nil {
		return failInstanceRuntime(out, err)
	}
	defer client.Close()
	state := client.State()
	if !state.Enrolled || state.Desired == nil {
		return failInstanceRuntime(out, instanceclient.ErrNotEnrolled)
	}
	result := instanceclient.EnrollmentResult{Desired: *state.Desired, State: state}
	outcome, err := localInstanceRuntimeApplyOutcome(config.StateRoot, state, deps)
	if err != nil {
		return failInstanceRuntime(out, err)
	}
	return emitInstanceRuntimeResult(out, "instance-runtime.status", result, config.StateRoot, false, true, outcome)
}

func parseInstanceRuntimeEnrollOptions(arguments []string) (instanceRuntimeEnrollOptions, error) {
	var options instanceRuntimeEnrollOptions
	set := newInstanceRuntimeFlagSet("instance-runtime enroll")
	set.StringVar(&options.server, "server", "", "serving HTTPS origin")
	set.StringVar(&options.tlsCA, "tls-ca", "", "explicit serving CA certificate")
	set.StringVar(&options.tlsPin, "tls-pin", "", "SHA256 leaf certificate pin")
	set.StringVar(&options.releasePublic, "release-public-key", "", "release signing public key")
	set.StringVar(&options.desiredPublic, "desired-public-key", "", "desired-state signing public key")
	set.StringVar(&options.adminUser, "admin-user", "", "existing unprivileged administrative user")
	set.StringVar(&options.stateRoot, "state-root", defaultInstanceRuntimeRoot, "private target runtime state root")
	set.DurationVar(&options.requestTimeout, "timeout", defaultRuntimeTimeout, "per-request HTTPS timeout")
	if err := parseInstanceRuntimeFlags(set, arguments); err != nil {
		return options, err
	}
	if options.server == "" || options.tlsCA == "" || options.tlsPin == "" || options.releasePublic == "" || options.desiredPublic == "" || options.adminUser == "" {
		return options, errors.New("--server, --tls-ca, --tls-pin, --release-public-key, --desired-public-key, and --admin-user are required")
	}
	if !validInstanceRuntimeAdmin(options.adminUser) {
		return options, errors.New("--admin-user must name a safe unprivileged account")
	}
	var err error
	options.stateRoot, err = cleanAbsoluteRuntimePath(options.stateRoot, false)
	if err != nil {
		return options, err
	}
	for name, path := range map[string]*string{
		"--tls-ca": &options.tlsCA, "--release-public-key": &options.releasePublic, "--desired-public-key": &options.desiredPublic,
	} {
		clean, cleanErr := cleanAbsoluteRuntimePath(*path, true)
		if cleanErr != nil {
			return options, fmt.Errorf("%s must be an absolute non-root file path", name)
		}
		*path = clean
	}
	return options, nil
}

func parseInstanceRuntimeStateOptions(name string, arguments []string) (string, error) {
	stateRoot := defaultInstanceRuntimeRoot
	set := newInstanceRuntimeFlagSet(name)
	set.StringVar(&stateRoot, "state-root", stateRoot, "private target runtime state root")
	if err := parseInstanceRuntimeFlags(set, arguments); err != nil {
		return "", err
	}
	return cleanAbsoluteRuntimePath(stateRoot, false)
}

func newInstanceRuntimeFlagSet(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.Usage = func() {}
	return set
}

func parseInstanceRuntimeFlags(set *flag.FlagSet, arguments []string) error {
	normalized, err := normalizeInterspersed(set, arguments)
	if err != nil {
		return err
	}
	if err := set.Parse(normalized); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return errRuntimeHelp
		}
		return err
	}
	if set.NArg() != 0 {
		return errors.New("instance bindings and credentials must be read from /dev/tty or stdin, never arguments")
	}
	return nil
}

func validateRuntimePlatform(out *emitter, deps instanceRuntimeDependencies) int {
	if deps.goos != "linux" {
		return out.fail("platform", "instance-runtime is supported only on Linux", "Run it on the managed Linux VM.", exitConfig)
	}
	if deps.uid == nil || deps.euid == nil || deps.uid() != 0 || deps.euid() != 0 {
		return out.fail("privilege", "instance-runtime requires real and effective UID 0", "Run from the VM console as root.", exitAuth)
	}
	return exitOK
}

func readInstanceRuntimeEnrollmentInput(input instanceRuntimeInput) (instanceRuntimeEnrollmentInput, error) {
	var result instanceRuntimeEnrollmentInput
	instanceBytes, err := input.ReadField("Instance name: ", false, 64)
	if err != nil {
		return result, errRuntimeInput
	}
	defer clearRuntimeBytes(instanceBytes)
	profileBytes, err := input.ReadField("Profile: ", false, 64)
	if err != nil {
		return result, errRuntimeInput
	}
	defer clearRuntimeBytes(profileBytes)
	id, err := input.ReadField("Enrollment ID: ", true, 128)
	if err != nil {
		return result, errRuntimeInput
	}
	if !runtimeIdentifierRE.Match(instanceBytes) || !runtimeIdentifierRE.Match(profileBytes) || !validRuntimeToken(id, 16) {
		clearRuntimeBytes(id)
		return result, errRuntimeInput
	}
	result.instance = string(instanceBytes)
	result.profile = string(profileBytes)
	result.enrollmentID = id
	return result, nil
}

func (input *instanceRuntimeEnrollmentInput) clear() {
	clearRuntimeBytes(input.enrollmentID)
	input.enrollmentID = nil
}

func (secret *deferredRuntimeSecret) Read(target []byte) (int, error) {
	if len(target) == 0 {
		return 0, nil
	}
	if secret.finished {
		return 0, io.EOF
	}
	if !secret.loaded {
		secret.loaded = true
		secret.data, secret.err = secret.input.ReadField("Enrollment secret: ", true, 128)
		if secret.err == nil {
			secret.err = secret.input.Finalize()
		}
		if secret.err != nil || !validRuntimeToken(secret.data, 32) {
			secret.clear()
			secret.err = errRuntimeInput
			return 0, secret.err
		}
	}
	if secret.err != nil {
		return 0, secret.err
	}
	count := copy(target, secret.data[secret.offset:])
	secret.offset += count
	if secret.offset == len(secret.data) {
		clearRuntimeBytes(secret.data)
		secret.data = nil
		secret.finished = true
	}
	return count, nil
}

func (secret *deferredRuntimeSecret) clear() {
	clearRuntimeBytes(secret.data)
	secret.data = nil
	secret.finished = true
}

func validRuntimeToken(value []byte, decodedLength int) bool {
	if len(value) == 0 || bytes.IndexAny(value, "\x00\r\n \t") >= 0 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(value))
	valid := err == nil && len(decoded) == decodedLength && string(value) == base64.RawURLEncoding.EncodeToString(decoded)
	clearRuntimeBytes(decoded)
	return valid
}

func newBoundInstanceRuntimeClient(config instanceRuntimeConfig, deps instanceRuntimeDependencies) (instanceRuntimeClient, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if err := validateInstanceRuntimeAdmin(config.AdminUser, deps); err != nil {
		return nil, err
	}
	caPEM, err := deps.readPublicFile(config.TLSCA, maxRuntimeCABytes)
	if err != nil {
		return nil, fmt.Errorf("%w: serving CA", errRuntimeConfiguration)
	}
	defer clearRuntimeBytes(caPEM)
	releasePEM, err := deps.readPublicFile(config.ReleasePublicKey, maxRuntimePublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: release public key", errRuntimeConfiguration)
	}
	defer clearRuntimeBytes(releasePEM)
	desiredPEM, err := deps.readPublicFile(config.DesiredPublicKey, maxRuntimePublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: desired-state public key", errRuntimeConfiguration)
	}
	defer clearRuntimeBytes(desiredPEM)
	releasePublic, err := signing.ParsePublicPEM(releasePEM)
	if err != nil {
		return nil, fmt.Errorf("%w: release public key", errRuntimeConfiguration)
	}
	desiredPublic, err := signing.ParsePublicPEM(desiredPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: desired-state public key", errRuntimeConfiguration)
	}
	timeout, err := time.ParseDuration(config.RequestTimeout)
	if err != nil {
		return nil, errRuntimeConfiguration
	}
	return deps.newClient(instanceclient.Config{
		StateDir: config.StateRoot, BaseURL: config.Server, CACertificatePEM: caPEM, TLSPin: config.TLSPin,
		ReleasePublicKey: releasePublic, DesiredPublicKey: desiredPublic,
		Instance: config.Instance, Profile: config.Profile, ExpectedIdentityKeyID: config.IdentityKeyID,
		RequestTimeout: timeout,
	})
}

func (config instanceRuntimeConfig) validate() error {
	if config.Schema != instanceRuntimeConfigSchema || !runtimeIdentifierRE.MatchString(config.Instance) ||
		!runtimeIdentifierRE.MatchString(config.Profile) ||
		!validInstanceRuntimeAdmin(config.AdminUser) ||
		(config.IdentityKeyID != "" && !runtimeKeyIDRE.MatchString(config.IdentityKeyID)) || config.EnrolledAt < 0 {
		return errRuntimeConfiguration
	}
	if config.Server == "" || config.TLSPin == "" || config.RequestTimeout == "" {
		return errRuntimeConfiguration
	}
	for _, path := range []string{config.TLSCA, config.ReleasePublicKey, config.DesiredPublicKey} {
		if _, err := cleanAbsoluteRuntimePath(path, true); err != nil {
			return errRuntimeConfiguration
		}
	}
	if clean, err := cleanAbsoluteRuntimePath(config.StateRoot, false); err != nil || clean != config.StateRoot {
		return errRuntimeConfiguration
	}
	return nil
}

func (config instanceRuntimeConfig) matchesPublicOptions(options instanceRuntimeEnrollOptions) bool {
	return config.Server == strings.TrimSuffix(options.server, "/") && config.TLSCA == options.tlsCA &&
		config.TLSPin == options.tlsPin && config.ReleasePublicKey == options.releasePublic &&
		config.DesiredPublicKey == options.desiredPublic && config.AdminUser == options.adminUser && config.StateRoot == options.stateRoot
}

func openInstanceRuntimeStore(stateRoot string) (*localstate.Store, error) {
	clean, err := cleanAbsoluteRuntimePath(stateRoot, false)
	if err != nil {
		return nil, errRuntimeConfiguration
	}
	store, err := localstate.Open(clean)
	if err != nil {
		return nil, fmt.Errorf("%w: private state root", errRuntimeConfiguration)
	}
	return store, nil
}

func readInstanceRuntimeConfig(store *localstate.Store) (instanceRuntimeConfig, bool, error) {
	var config instanceRuntimeConfig
	if err := store.ReadJSON(instanceRuntimeConfigPath, &config); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config, false, nil
		}
		return config, false, fmt.Errorf("%w: runtime config", errRuntimeConfiguration)
	}
	if err := config.validate(); err != nil || config.StateRoot != store.Root() || config.IdentityKeyID == "" || config.EnrolledAt <= 0 {
		return config, false, errRuntimeConfiguration
	}
	return config, true, nil
}

func persistInstanceRuntimeConfig(store *localstate.Store, config instanceRuntimeConfig) error {
	if err := config.validate(); err != nil || config.IdentityKeyID == "" || config.EnrolledAt <= 0 || config.StateRoot != store.Root() {
		return errRuntimeConfiguration
	}
	existing, exists, err := readInstanceRuntimeConfig(store)
	if err != nil {
		return err
	}
	if exists {
		if !existing.sameBinding(config) {
			return errRuntimeConflict
		}
		return nil
	}
	return store.WriteJSON(instanceRuntimeConfigPath, config)
}

func (config instanceRuntimeConfig) sameBinding(other instanceRuntimeConfig) bool {
	config.EnrolledAt = 0
	other.EnrolledAt = 0
	return config == other
}

func loadConfiguredInstanceRuntime(stateRoot string, deps instanceRuntimeDependencies) (instanceRuntimeConfig, instanceRuntimeClient, error) {
	store, err := openInstanceRuntimeStore(stateRoot)
	if err != nil {
		return instanceRuntimeConfig{}, nil, err
	}
	config, exists, err := readInstanceRuntimeConfig(store)
	if err != nil {
		return config, nil, err
	}
	if !exists {
		return config, nil, errRuntimeConfiguration
	}
	client, err := newBoundInstanceRuntimeClient(config, deps)
	return config, client, err
}

func validateInstanceRuntimeAdmin(name string, deps instanceRuntimeDependencies) error {
	if !validInstanceRuntimeAdmin(name) || deps.validateAdmin == nil {
		return errRuntimeConfiguration
	}
	if err := deps.validateAdmin(name); err != nil {
		return fmt.Errorf("%w: administrative user", errRuntimeConfiguration)
	}
	return nil
}

func validInstanceRuntimeAdmin(name string) bool {
	return runtimeAdminUserRE.MatchString(name) && name != "root" && name != "malwarelab"
}

func loadInstanceRuntimeTrust(config instanceRuntimeConfig, deps instanceRuntimeDependencies) (instanceRuntimeTrust, error) {
	var trust instanceRuntimeTrust
	if deps.readPublicFile == nil {
		return trust, errRuntimeConfiguration
	}
	releasePEM, err := deps.readPublicFile(config.ReleasePublicKey, maxRuntimePublicKeyBytes)
	if err != nil {
		return trust, fmt.Errorf("%w: release public key", errRuntimeConfiguration)
	}
	defer clearRuntimeBytes(releasePEM)
	desiredPEM, err := deps.readPublicFile(config.DesiredPublicKey, maxRuntimePublicKeyBytes)
	if err != nil {
		return trust, fmt.Errorf("%w: desired-state public key", errRuntimeConfiguration)
	}
	defer clearRuntimeBytes(desiredPEM)
	trust.releasePublic, err = signing.ParsePublicPEM(releasePEM)
	if err != nil {
		return instanceRuntimeTrust{}, fmt.Errorf("%w: release public key", errRuntimeConfiguration)
	}
	trust.desiredPublic, err = signing.ParsePublicPEM(desiredPEM)
	if err != nil || bytes.Equal(trust.releasePublic, trust.desiredPublic) {
		return instanceRuntimeTrust{}, fmt.Errorf("%w: desired-state public key", errRuntimeConfiguration)
	}
	return trust, nil
}

func applyInstanceRuntimeResult(
	ctx context.Context,
	config instanceRuntimeConfig,
	client instanceRuntimeClient,
	result instanceclient.EnrollmentResult,
	deps instanceRuntimeDependencies,
) (instanceRuntimeApplyOutcome, error) {
	outcome := instanceRuntimeApplyOutcome{}
	if ctx == nil || client == nil || deps.loadCheckpoint == nil || deps.runApply == nil || deps.revoke == nil ||
		deps.now == nil || deps.readSSHHostKey == nil || deps.sshConnection == nil {
		return outcome, errRuntimeConfiguration
	}
	checkpoint, _, err := deps.loadCheckpoint(config.StateRoot)
	if err != nil {
		return outcome, err
	}
	outcome.AppliedGeneration = checkpoint.DesiredGeneration
	trust, err := loadInstanceRuntimeTrust(config, deps)
	if err != nil {
		return outcome, err
	}
	registry, err := profiles.Builtin()
	if err != nil {
		return outcome, errRuntimeConfiguration
	}
	plan, err := applyplan.Build(registry, result.Release, trust.releasePublic, result.Desired, trust.desiredPublic, applyplan.Options{
		Instance: config.Instance, Profile: config.Profile, GOARCH: deps.goarch,
		Now: deps.now().UTC(), Checkpoint: checkpoint,
	})
	if errors.Is(err, applyplan.ErrRevoked) {
		outcome.Revoked = true
		if revokeErr := deps.revoke(ctx, config.StateRoot, config.AdminUser, config.Profile); revokeErr != nil {
			return outcome, fmt.Errorf("%w: %v", errRuntimeFailClosed, revokeErr)
		}
		outcome.FailClosed = true
		if reportErr := reportInstanceRuntimeRevocation(ctx, config, client, result, checkpoint, deps); reportErr != nil {
			outcome.ReportingDegraded = true
			return outcome, fmt.Errorf("%w: %v", errRuntimeReporting, reportErr)
		}
		return outcome, nil
	}
	if err != nil {
		return outcome, err
	}
	outcome.PlanID = plan.ID
	reporter, err := newInstanceRuntimeReporter(config, client, plan, checkpoint, deps)
	if err != nil {
		return outcome, err
	}
	if err := reporter.before(ctx); err != nil {
		return outcome, err
	}
	applyResult, applyErr := deps.runApply(ctx, targetapply.Config{
		StateRoot: config.StateRoot, AdminUser: config.AdminUser, Plan: plan,
		FetchArtifact: func(fetchContext context.Context, artifact applyplan.Artifact, destination io.Writer) error {
			component, matchErr := releaseComponentForRuntimeArtifact(result.Release, artifact)
			if matchErr != nil {
				return matchErr
			}
			return client.DownloadArtifact(fetchContext, result.Release, component, destination)
		},
		Event: reporter.event, Now: deps.now, SSHConnection: deps.sshConnection(),
	})
	if applyErr != nil {
		reporter.afterFailure(ctx, applyResult.Journal, applyErr)
		return outcome, fmt.Errorf("%w: %w", errRuntimeApply, applyErr)
	}
	if applyResult.HandoffRequired {
		outcome.HandoffRequired = true
		reporter.afterHandoff(ctx)
		if reportErr := reporter.err(); reportErr != nil {
			outcome.ReportingDegraded = true
			return outcome, fmt.Errorf("%w: %v", errRuntimeReporting, reportErr)
		}
		return outcome, nil
	}
	checkpointResult := applyResult.Checkpoint
	if checkpointResult.ReleaseGeneration != plan.ReleaseGeneration || checkpointResult.ReleaseSet != plan.ReleaseSet ||
		checkpointResult.DesiredGeneration != plan.DesiredGeneration || checkpointResult.DesiredStateID != plan.DesiredStateID ||
		checkpointResult.PlanID != plan.ID {
		reporter.afterFailure(ctx, applyResult.Journal, targetapply.ErrInvalidConfig)
		return outcome, fmt.Errorf("%w: checkpoint did not bind the completed plan", errRuntimeApply)
	}
	outcome.Applied = true
	outcome.AppliedGeneration = checkpointResult.DesiredGeneration
	reporter.afterSuccess(ctx)
	if reportErr := reporter.err(); reportErr != nil {
		outcome.ReportingDegraded = true
		return outcome, fmt.Errorf("%w: %v", errRuntimeReporting, reportErr)
	}
	return outcome, nil
}

func reportInstanceRuntimeRevocation(
	ctx context.Context,
	config instanceRuntimeConfig,
	client instanceRuntimeClient,
	result instanceclient.EnrollmentResult,
	checkpoint applyplan.Checkpoint,
	deps instanceRuntimeDependencies,
) error {
	version := "unknown"
	matches := 0
	for _, component := range result.Release.Manifest.Components {
		if component.Name == "ssh" && (component.Target == "any" || component.Target == "linux-"+deps.goarch) {
			version = component.Version
			matches++
		}
	}
	if matches != 1 {
		version = "unknown"
	}
	report := serving.NormalizeStatus(serving.StatusReport{
		Schema: serving.StatusSchema, Instance: config.Instance, Profile: config.Profile,
		DesiredGeneration: result.Desired.State.Generation, AppliedGeneration: checkpoint.DesiredGeneration,
		ReleaseSet: result.Desired.State.ReleaseSet, State: "revoked", Revoked: true, FailClosed: true,
		Components: []serving.ComponentStatus{{Name: "ssh", Version: version, State: "blocked", Code: "revoked"}},
		ReportedAt: deps.now().UTC().Unix(),
	})
	var failures []error
	if err := client.ReportStatus(ctx, report); err != nil {
		failures = append(failures, err)
	}
	sequence, err := allocateInstanceRuntimeLogSequence(config.StateRoot, "ssh")
	if err != nil {
		failures = append(failures, err)
	} else if err := client.ReportLogs(ctx, serving.LogBatch{
		Schema: serving.LogSchema, Instance: config.Instance, Profile: config.Profile, Component: "ssh",
		Events: []serving.LogEvent{{
			Sequence: sequence, Timestamp: deps.now().UTC().Unix(), Level: "critical",
			Event: "phase_fail_closed", Code: "revoked",
		}},
	}); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func releaseComponentForRuntimeArtifact(signed release.SignedManifest, artifact applyplan.Artifact) (release.Component, error) {
	wanted := release.Component{
		Name: artifact.Component, Version: artifact.Version, Target: artifact.Target,
		Artifact: artifact.Path, Digest: artifact.Digest, Size: artifact.Size,
	}
	matched := 0
	for _, component := range signed.Manifest.Components {
		if component == wanted {
			matched++
		}
	}
	if matched != 1 {
		return release.Component{}, instanceclient.ErrArtifactNotBound
	}
	return wanted, nil
}

func localInstanceRuntimeApplyOutcome(stateRoot string, state instanceclient.State, deps instanceRuntimeDependencies) (instanceRuntimeApplyOutcome, error) {
	outcome := instanceRuntimeApplyOutcome{}
	if deps.loadCheckpoint == nil || state.Desired == nil {
		return outcome, errRuntimeConfiguration
	}
	checkpoint, _, err := deps.loadCheckpoint(stateRoot)
	if err != nil {
		return outcome, err
	}
	outcome.Revoked = state.Desired.State.Revoked
	outcome.AppliedGeneration = checkpoint.DesiredGeneration
	outcome.PlanID = ""
	if checkpoint.DesiredGeneration == state.Desired.State.Generation && checkpoint.ReleaseGeneration == state.ReleaseGeneration &&
		checkpoint.ReleaseSet == state.ReleaseSet && !state.Desired.State.Revoked {
		outcome.Applied = true
	}
	return outcome, nil
}

type instanceRuntimeReporter struct {
	config     instanceRuntimeConfig
	client     instanceRuntimeClient
	plan       applyplan.Plan
	checkpoint applyplan.Checkpoint
	deps       instanceRuntimeDependencies
	components map[string]serving.ComponentStatus
	firstError error
	hostKey    string
	ctx        context.Context
}

func newInstanceRuntimeReporter(
	config instanceRuntimeConfig,
	client instanceRuntimeClient,
	plan applyplan.Plan,
	checkpoint applyplan.Checkpoint,
	deps instanceRuntimeDependencies,
) (*instanceRuntimeReporter, error) {
	reporter := &instanceRuntimeReporter{
		config: config, client: client, plan: plan, checkpoint: checkpoint, deps: deps,
		components: make(map[string]serving.ComponentStatus, len(plan.Phases)),
	}
	for _, phase := range plan.Phases {
		if !runtimeLogComponentAllowed(phase.Profile) || len(phase.Steps) == 0 {
			return nil, errRuntimeConfiguration
		}
		reporter.components[phase.Profile] = serving.ComponentStatus{
			Name: phase.Profile, Version: phase.Steps[0].Artifact.Version, State: "pending",
		}
	}
	return reporter, nil
}

func (reporter *instanceRuntimeReporter) before(ctx context.Context) error {
	reporter.ctx = ctx
	statusErr := reporter.reportStatus(ctx, "pending", reporter.checkpoint.DesiredGeneration, false)
	logErr := reporter.reportLog(ctx, "instance-runtime", "reconcile_started", "")
	if statusErr != nil {
		return statusErr
	}
	return logErr
}

func (reporter *instanceRuntimeReporter) event(phase, state, detail string) {
	event, componentState, valid := runtimeReconcileEvent(state)
	component, exists := reporter.components[phase]
	if !valid || !exists {
		reporter.record(errRuntimeConfiguration)
		return
	}
	code := ""
	if event == "phase_failed" || event == "phase_fail_closed" {
		code = runtimeReconcileCode(detail)
	}
	component.State = componentState
	component.Code = code
	reporter.components[phase] = component
	ctx := reporter.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	reporter.record(reporter.reportLog(ctx, phase, event, code))
	reporter.record(reporter.reportStatus(ctx, reporter.overallState(), reporter.checkpoint.DesiredGeneration, reporter.sshReady()))
}

func (reporter *instanceRuntimeReporter) afterHandoff(ctx context.Context) {
	if component, exists := reporter.components["flow"]; exists {
		component.State, component.Code = "ready", ""
		reporter.components["flow"] = component
	}
	// the previous apply generation remains authoritative until the new binary
	// finishes the complete plan on the next timer invocation.
	reporter.record(reporter.reportStatus(ctx, "applying", reporter.checkpoint.DesiredGeneration, false))
}

func (reporter *instanceRuntimeReporter) afterSuccess(ctx context.Context) {
	for name, component := range reporter.components {
		component.State, component.Code = "ready", ""
		reporter.components[name] = component
	}
	reporter.record(reporter.reportLog(ctx, "instance-runtime", "reconcile_complete", ""))
	reporter.record(reporter.reportStatus(ctx, "ready", reporter.plan.DesiredGeneration, true))
}

func (reporter *instanceRuntimeReporter) afterFailure(ctx context.Context, journal reconcile.Journal, cause error) {
	for _, phase := range journal.Phases {
		component, exists := reporter.components[phase.Name]
		if !exists {
			continue
		}
		component.Code = ""
		switch phase.Status {
		case reconcile.Complete:
			component.State = "ready"
		case reconcile.Preflight, reconcile.Applying, reconcile.Verifying:
			component.State = "applying"
		case reconcile.Failed:
			component.State, component.Code = "failed", runtimeReconcileCode(phase.ErrorCode)
		case reconcile.FailClosed:
			component.State, component.Code = "blocked", runtimeReconcileCode(phase.ErrorCode)
		default:
			component.State = "pending"
		}
		reporter.components[phase.Name] = component
	}
	code := "phase_failed"
	if errors.Is(cause, reconcile.ErrBusy) {
		code = "apply_busy"
	}
	reporter.record(reporter.reportLog(ctx, "instance-runtime", "reconcile_failed", code))
	reporter.record(reporter.reportStatus(ctx, reporter.overallState(), reporter.checkpoint.DesiredGeneration, reporter.sshReady()))
}

func (reporter *instanceRuntimeReporter) reportStatus(ctx context.Context, state string, appliedGeneration uint64, requireHostKey bool) error {
	if requireHostKey && reporter.hostKey == "" {
		hostKey, err := reporter.deps.readSSHHostKey()
		if err != nil {
			return err
		}
		reporter.hostKey = hostKey
	}
	components := make([]serving.ComponentStatus, 0, len(reporter.components))
	for _, component := range reporter.components {
		components = append(components, component)
	}
	sort.Slice(components, func(left, right int) bool { return components[left].Name < components[right].Name })
	report := serving.NormalizeStatus(serving.StatusReport{
		Schema: serving.StatusSchema, Instance: reporter.config.Instance, Profile: reporter.config.Profile,
		DesiredGeneration: reporter.plan.DesiredGeneration, AppliedGeneration: appliedGeneration,
		ReleaseSet: reporter.plan.ReleaseSet, State: state, Components: components,
		SSHHostKey: reporter.hostKey, ReportedAt: reporter.deps.now().UTC().Unix(),
	})
	return reporter.client.ReportStatus(ctx, report)
}

func (reporter *instanceRuntimeReporter) reportLog(ctx context.Context, component, event, code string) error {
	sequence, err := allocateInstanceRuntimeLogSequence(reporter.config.StateRoot, component)
	if err != nil {
		return err
	}
	return reporter.client.ReportLogs(ctx, serving.LogBatch{
		Schema: serving.LogSchema, Instance: reporter.config.Instance, Profile: reporter.config.Profile,
		Component: component, Events: []serving.LogEvent{{
			Sequence: sequence, Timestamp: reporter.deps.now().UTC().Unix(), Level: runtimeLogLevel(event), Event: event, Code: code,
		}},
	})
}

func (reporter *instanceRuntimeReporter) overallState() string {
	allReady := true
	state := "applying"
	for _, component := range reporter.components {
		switch component.State {
		case "blocked":
			return "blocked"
		case "failed":
			state = "failed"
		case "ready":
		default:
			allReady = false
		}
	}
	if state == "failed" {
		return state
	}
	if allReady {
		return "ready"
	}
	return "applying"
}

func (reporter *instanceRuntimeReporter) sshReady() bool {
	component, exists := reporter.components["ssh"]
	return exists && component.State == "ready"
}

func (reporter *instanceRuntimeReporter) record(err error) {
	if err != nil && reporter.firstError == nil {
		reporter.firstError = err
	}
}

func (reporter *instanceRuntimeReporter) err() error { return reporter.firstError }

func runtimeReconcileEvent(state string) (string, string, bool) {
	switch state {
	case "preflight":
		return "phase_preflight", "applying", true
	case "applying":
		return "phase_applying", "applying", true
	case "verifying":
		return "phase_verifying", "applying", true
	case "complete":
		return "phase_complete", "ready", true
	case "failed":
		return "phase_failed", "failed", true
	case "fail_closed":
		return "phase_fail_closed", "blocked", true
	default:
		return "", "", false
	}
}

func runtimeReconcileCode(code string) string {
	switch code {
	case "artifact_verification", "installer_failed", "rollback_failed", "phase_failed", "apply_busy":
		return code
	default:
		return "phase_failed"
	}
}

func runtimeLogLevel(event string) string {
	switch event {
	case "phase_failed", "reconcile_failed":
		return "error"
	case "phase_fail_closed":
		return "critical"
	default:
		return "info"
	}
}

func runtimeLogComponentAllowed(component string) bool {
	switch component {
	case "flow", "instance-runtime", "ssh", "ssh-gui", "vpn", "vpn-pbp-de", "pbp", "decepticon", "examstation":
		return true
	default:
		return false
	}
}

func allocateInstanceRuntimeLogSequence(stateRoot, component string) (uint64, error) {
	if !runtimeLogComponentAllowed(component) {
		return 0, errRuntimeConfiguration
	}
	store, err := openInstanceRuntimeStore(stateRoot)
	if err != nil {
		return 0, err
	}
	var sequence uint64
	err = store.WithLock(instanceRuntimeReportLock, func() error {
		state := instanceRuntimeLogSequenceState{Schema: 1, Last: map[string]uint64{}}
		if err := store.ReadJSON(instanceRuntimeReportPath, &state); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else if err := validateInstanceRuntimeLogSequenceState(state); err != nil {
			return err
		}
		if state.Last == nil {
			state.Last = map[string]uint64{}
		}
		last := state.Last[component]
		if last == ^uint64(0) {
			return errRuntimeConfiguration
		}
		sequence = last + 1
		state.Last[component] = sequence
		return store.WriteJSON(instanceRuntimeReportPath, state)
	})
	return sequence, err
}

func validateInstanceRuntimeLogSequenceState(state instanceRuntimeLogSequenceState) error {
	if state.Schema != 1 || state.Last == nil || len(state.Last) > serving.MaxLogComponents {
		return errRuntimeConfiguration
	}
	for component, sequence := range state.Last {
		if !runtimeLogComponentAllowed(component) || sequence == 0 {
			return errRuntimeConfiguration
		}
	}
	return nil
}

func readRuntimeSSHHostKey() (string, error) {
	data, err := readRootOwnedRuntimePublicFile("/etc/ssh/ssh_host_ed25519_key.pub", maxRuntimeSSHHostKeyBytes)
	if err != nil {
		return "", err
	}
	defer clearRuntimeBytes(data)
	return normalizeRuntimeSSHHostKey(data)
}

func normalizeRuntimeSSHHostKey(data []byte) (string, error) {
	value := strings.TrimSpace(string(data))
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errRuntimeConfiguration
	}
	normalized, _, err := sshkeys.ValidateEd25519PublicKey(value)
	if err != nil {
		return "", errRuntimeConfiguration
	}
	fields := strings.Fields(normalized)
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		return "", errRuntimeConfiguration
	}
	return strings.Join(fields[:2], " "), nil
}

func shouldRecoverInstanceEnrollment(err error) bool {
	if errors.Is(err, instanceclient.ErrEnrollmentOutcomeUnknown) || errors.Is(err, instanceclient.ErrAlreadyEnrolled) {
		return true
	}
	var httpError *instanceclient.HTTPError
	return errors.As(err, &httpError) && httpError.StatusCode == http.StatusUnauthorized && httpError.Code == "enrollment_rejected"
}

func finishInstanceRuntimeApply(
	out *emitter,
	command string,
	result instanceclient.EnrollmentResult,
	stateRoot string,
	recovered, localOnly bool,
	outcome instanceRuntimeApplyOutcome,
	err error,
) int {
	if err == nil {
		return emitInstanceRuntimeResult(out, command, result, stateRoot, recovered, localOnly, outcome)
	}
	if (outcome.Applied || (outcome.Revoked && outcome.FailClosed)) && errors.Is(err, errRuntimeReporting) {
		return emitInstanceRuntimeReportingPartial(out, command, result, stateRoot, recovered, localOnly, outcome)
	}
	return failInstanceRuntime(out, err)
}

func instanceRuntimeResultData(
	result instanceclient.EnrollmentResult,
	stateRoot string,
	recovered, localOnly bool,
	outcome instanceRuntimeApplyOutcome,
) (map[string]any, error) {
	state := result.State
	if state.Desired == nil && result.Desired.State.Generation != 0 {
		desired := result.Desired
		state.Desired = &desired
	}
	if !state.Enrolled || state.Desired == nil {
		return nil, instanceclient.ErrInvalidState
	}
	return map[string]any{
		"enrolled": true, "identity_key_id": state.IdentityKeyID,
		"release_set": state.Desired.State.ReleaseSet, "desired_generation": state.Desired.State.Generation,
		"revoked": state.Desired.State.Revoked, "expires_at": state.Desired.State.ExpiresAt,
		"recovered": recovered, "local_only": localOnly, "profile_applied": outcome.Applied,
		"fail_closed": outcome.FailClosed, "reporting_degraded": outcome.ReportingDegraded,
		"runtime_handoff": outcome.HandoffRequired,
		"plan_id":         outcome.PlanID, "applied_generation": outcome.AppliedGeneration,
		"state_root": stateRoot,
	}, nil
}

func emitInstanceRuntimeResult(
	out *emitter,
	command string,
	result instanceclient.EnrollmentResult,
	stateRoot string,
	recovered, localOnly bool,
	outcome instanceRuntimeApplyOutcome,
) int {
	data, err := instanceRuntimeResultData(result, stateRoot, recovered, localOnly, outcome)
	if err != nil {
		return failInstanceRuntime(out, err)
	}
	desiredGeneration := result.Desired.State.Generation
	if result.State.Desired != nil {
		desiredGeneration = result.State.Desired.State.Generation
	}
	human := fmt.Sprintf("Target identity enrolled; desired generation %d verified.", desiredGeneration)
	switch {
	case outcome.HandoffRequired:
		human = "Flow runtime updated atomically; profile reconciliation will resume with the new binary on the next timer run."
	case outcome.Applied:
		human = fmt.Sprintf("Target profile applied at desired generation %d.", outcome.AppliedGeneration)
	case outcome.Revoked && outcome.FailClosed:
		human = "Revoked desired state verified; local access was placed fail-closed and no installer ran."
	case localOnly:
		human += " Local status shows no matching completed apply checkpoint."
	}
	return out.success(command, data, human)
}

func emitInstanceRuntimeReportingPartial(
	out *emitter,
	command string,
	result instanceclient.EnrollmentResult,
	stateRoot string,
	recovered, localOnly bool,
	outcome instanceRuntimeApplyOutcome,
) int {
	data, err := instanceRuntimeResultData(result, stateRoot, recovered, localOnly, outcome)
	if err != nil {
		return failInstanceRuntime(out, err)
	}
	if out.json {
		message := "profile applied, but one or more signed status or finite log reports did not complete"
		next := "Retry flow instance-runtime reconcile; the completed checkpoint makes apply idempotent."
		if outcome.HandoffRequired {
			message = "flow runtime updated, but its applying status acknowledgement did not complete"
			next = "The old process stopped before profile phases; the persistent timer will resume with the new binary."
		} else if outcome.Revoked && outcome.FailClosed {
			message = "local fail-closed revocation succeeded, but its signed status or finite log acknowledgement did not complete"
			next = "The target remains fail-closed; the persistent timer will retry the acknowledgement."
		}
		_ = json.NewEncoder(out.stderr).Encode(map[string]any{
			"ok": false, "command": command, "data": data,
			"error": map[string]any{
				"code":    "reporting_partial",
				"message": message,
				"next":    next,
			},
		})
	} else {
		if outcome.HandoffRequired {
			fmt.Fprintln(out.stderr, "ERROR [reporting_partial]: Flow runtime updated, but its applying status acknowledgement was incomplete.")
			fmt.Fprintln(out.stderr, "Next: The old process stopped before profile phases; the persistent timer will resume with the new binary.")
		} else if outcome.Revoked && outcome.FailClosed {
			fmt.Fprintln(out.stderr, "ERROR [reporting_partial]: Local fail-closed revocation succeeded, but its signed acknowledgement was incomplete.")
			fmt.Fprintln(out.stderr, "Next: The target remains fail-closed; the persistent timer will retry the acknowledgement.")
		} else {
			fmt.Fprintln(out.stderr, "ERROR [reporting_partial]: Profile applied, but signed status or finite log reporting was incomplete.")
			fmt.Fprintln(out.stderr, "Next: Retry flow instance-runtime reconcile; the completed checkpoint makes apply idempotent.")
		}
	}
	return exitPartial
}

func failInstanceRuntime(out *emitter, err error) int {
	var httpError *instanceclient.HTTPError
	var networkError net.Error
	switch {
	case errors.Is(err, errRuntimeInput):
		return out.fail("input", "target runtime input was invalid", "Retry through /dev/tty or four bounded stdin lines.", exitAuth)
	case errors.Is(err, instanceclient.ErrInvalidCredential), errors.As(err, &httpError) && httpError.StatusCode == http.StatusUnauthorized:
		return out.fail("authentication", "enrollment or instance authentication was rejected", "Verify or reissue the bound enrollment credential.", exitAuth)
	case errors.Is(err, instanceclient.ErrIdentityConflict), errors.Is(err, instanceclient.ErrInvalidState), errors.Is(err, errRuntimeConflict):
		return out.fail("state_conflict", "runtime state conflicts with the stable instance identity or trust binding", "Recover the original identity; do not generate a replacement.", exitConflict)
	case errors.Is(err, reconcile.ErrBusy):
		return out.fail("apply_busy", "another profile reconciliation is already running", "Wait for the active reconciliation, then retry.", exitConflict)
	case errors.Is(err, errRuntimeService):
		return out.fail("reconcile_service", "the persistent target reconcile timer could not be installed safely", "Repair /usr/local/bin/flow and systemd, then rerun the same enrollment without issuing a new code.", exitConfig)
	case errors.Is(err, errRuntimeFailClosed):
		return out.fail("revocation_failed", "revocation was verified but local fail-closed enforcement could not be confirmed", "Use the provider console to isolate the VM and inspect protected target logs.", exitPartial)
	case errors.Is(err, errRuntimeApply):
		return out.fail("apply_failed", "the fixed profile apply failed and did not advance the completed checkpoint", "Inspect flow instance logs and protected target logs, then retry to resume.", exitFailure)
	case errors.As(err, &httpError) && httpError.StatusCode >= http.StatusInternalServerError,
		errors.As(err, &networkError), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return out.fail("remote", "serving could not be reached or completed the request", "Check outbound HTTPS and serving health, then retry.", exitRemote)
	case errors.Is(err, instanceclient.ErrTLSPin), errors.Is(err, signing.ErrInvalidSignature),
		errors.Is(err, release.ErrInvalidManifest), errors.Is(err, release.ErrArtifactTampered),
		errors.Is(err, instanceclient.ErrArtifactNotBound), errors.Is(err, applyplan.ErrMissingArtifact),
		errors.Is(err, applyplan.ErrAmbiguousArtifact), errors.Is(err, applyplan.ErrRevokedArtifact),
		errors.Is(err, applyplan.ErrProfileMismatch), errors.Is(err, applyplan.ErrRollback),
		errors.Is(err, enrollment.ErrBinding), errors.Is(err, enrollment.ErrInvalidDesiredState),
		errors.Is(err, enrollment.ErrExpired), errors.Is(err, enrollment.ErrStaleRequest),
		errors.Is(err, instanceclient.ErrResponseTooLarge), errors.Is(err, instanceclient.ErrUnexpectedResponse):
		return out.fail("verification", "serving trust, signed release, or desired-state verification failed", "Check CA/pin/signing keys and serving release health.", exitVerify)
	case errors.Is(err, instanceclient.ErrNotEnrolled):
		return out.fail("not_enrolled", "target runtime is not enrolled", "Run flow instance-runtime enroll.", exitConflict)
	default:
		return out.fail("config", "target runtime configuration or private state is invalid", "Check root ownership, 0600/0700 modes, trust files, and state-root.", exitConfig)
	}
}

func cleanAbsoluteRuntimePath(path string, file bool) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errRuntimeConfiguration
	}
	clean := filepath.Clean(path)
	if clean == string(filepath.Separator) || (file && filepath.Base(clean) == ".") {
		return "", errRuntimeConfiguration
	}
	return clean, nil
}

func clearRuntimeBytes(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

func isRuntimeHelp(value string) bool { return value == "help" || value == "--help" || value == "-h" }

const instanceRuntimeHelpText = `Dynamicflow target runtime (Linux root only)

Usage:
  flow [--json] instance-runtime enroll --server URL --tls-ca PATH --tls-pin PIN \
    --release-public-key PATH --desired-public-key PATH --admin-user NAME \
    [--state-root PATH]
  flow [--json] instance-runtime reconcile [--state-root PATH]
  flow [--json] instance-runtime status [--state-root PATH]
  flow instance-runtime secret <reveal|rotate> --secret vnc

Enrollment input is never accepted through arguments or environment variables.
With a terminal, flow prompts for instance name and profile and reads enrollment
ID and secret without echo. With non-terminal stdin, provide exactly four lines:

  instance name
  profile
  enrollment ID
  enrollment secret

--admin-user is public configuration and must name the existing unprivileged
administrative account from which the bootstrap was invoked. The runtime verifies
TLS CA and leaf pin, release and desired-state signatures, derives the compiled-in
profile graph, downloads only exact signed artifacts, and runs the fixed resumable
installers. Enrollment also installs dynamicflow-instance-reconcile.timer before
reading credentials; its one-shot service remains inert until runtime-config.json
is committed, then retries signed desired state over outbound HTTPS every five
minutes and after reboot. Status reads verified local state and makes no network
request.

The secret subcommand is a fixed root-only one-shot used only by the audited,
pinned flow instance secret operator command. It accepts no paths or credential
input and writes the deliberately requested credential only to stdout.
`
