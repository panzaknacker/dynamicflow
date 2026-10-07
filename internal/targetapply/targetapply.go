// Package targetapply executes the small, fixed set of Dynamicflow profile
// installers. It consumes an already signature-verified apply plan and has no
// generic command or remotely supplied argument facility.
package targetapply

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"dynamicflow/internal/applyplan"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/reconcile"
	"dynamicflow/internal/signing"
)

const (
	checkpointSchema  = 1
	maxCommandLog     = int64(32 << 20)
	maxArtifactSize   = int64(4 << 30)
	maxCommandOutput  = int64(1 << 20)
	maxLogLine        = 64 << 10
	maxAuthorizedKeys = int64(512 << 10)
	vncSecretPath     = "/root/.vm-bootstrap-vnc-malwarelab"
	vncUser           = "malwarelab"
	vncDisplay        = "1"
	vncPort           = "5901"
	vncUnit           = "tigervncserver@:1.service"
	vncAccountMarker  = "/var/lib/vm-bootstrap/gui-user-malwarelab"
)

var (
	ErrInvalidConfig        = errors.New("invalid target apply configuration")
	ErrUnsupportedProfile   = errors.New("profile has no fixed target installer")
	ErrArtifactVerification = errors.New("downloaded artifact failed verification")
	ErrPersonaChanged       = errors.New("stable PBP persona changed")
	identifierRE            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	userRE                  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
	digestRE                = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	personaRE               = regexp.MustCompile(`^[0-9a-f]{64}$`)
	jsonNumberRE            = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:[.][0-9]+)?(?:[eE][+-]?[0-9]+)?$`)
	safeNameRE              = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	versionRE               = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9._-]*)?$`)
	secretLikeRE            = regexp.MustCompile(`[A-Za-z0-9_=-]{24,}|[0-9]{10,}`)
)

// FetchArtifact must stream exactly the signed artifact into destination. The
// caller verifies size and digest again before activation.
type FetchArtifact func(context.Context, applyplan.Artifact, io.Writer) error

type EventFunc func(phase, state, code string)

type Config struct {
	StateRoot     string
	AdminUser     string
	Plan          applyplan.Plan
	FetchArtifact FetchArtifact
	Event         EventFunc
	Now           func() time.Time
	SSHConnection string
}

type Checkpoint struct {
	Schema            int    `json:"schema"`
	ReleaseGeneration uint64 `json:"release_generation"`
	ReleaseSet        string `json:"release_set"`
	DesiredGeneration uint64 `json:"desired_generation"`
	DesiredStateID    string `json:"desired_state_id"`
	PlanID            string `json:"plan_id"`
	PersonaID         string `json:"persona_id,omitempty"`
	AppliedAt         int64  `json:"applied_at"`
}

type Result struct {
	PlanID          string            `json:"plan_id"`
	HandoffRequired bool              `json:"handoff_required,omitempty"`
	Checkpoint      Checkpoint        `json:"checkpoint"`
	Journal         reconcile.Journal `json:"journal"`
	LogPaths        map[string]string `json:"log_paths"`
}

type runner struct {
	config             Config
	store              *localstate.Store
	artifactsDir       string
	runtimeRecoveryDir string
	stagingDir         string
	logsDir            string
	logPaths           map[string]string
}

// LoadCheckpoint returns the last fully applied content-bound state. A
// missing checkpoint is represented by the zero value.
func LoadCheckpoint(stateRoot string) (applyplan.Checkpoint, string, error) {
	store, err := localstate.Open(stateRoot)
	if err != nil {
		return applyplan.Checkpoint{}, "", err
	}
	var persisted Checkpoint
	if err := store.ReadJSON("apply/checkpoint.json", &persisted); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return applyplan.Checkpoint{}, "", nil
		}
		return applyplan.Checkpoint{}, "", err
	}
	if err := validateCheckpoint(persisted); err != nil {
		return applyplan.Checkpoint{}, "", err
	}
	return applyplan.Checkpoint{
		ReleaseGeneration: persisted.ReleaseGeneration, ReleaseSet: persisted.ReleaseSet,
		DesiredGeneration: persisted.DesiredGeneration, DesiredStateID: persisted.DesiredStateID,
	}, persisted.PersonaID, nil
}

// Run downloads immutable artifacts, then executes dependency-ordered phases
// through reconcile's durable lock/journal. A checkpoint is advanced only
// after every phase verifies.
func Run(ctx context.Context, config Config) (Result, error) {
	if ctx == nil || config.FetchArtifact == nil || validatePlan(config.Plan) != nil ||
		!filepath.IsAbs(config.StateRoot) || filepath.Clean(config.StateRoot) == "/" ||
		!userRE.MatchString(config.AdminUser) || config.AdminUser == "root" || config.AdminUser == "malwarelab" {
		return Result{}, ErrInvalidConfig
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Plan.Profile != "ssh" && config.Plan.Profile != "ssh-gui" && config.Plan.Profile != "vpn" && config.Plan.Profile != "pbp" {
		return Result{}, fmt.Errorf("%w: %s", ErrUnsupportedProfile, config.Plan.Profile)
	}
	if err := validateSSHConnection(config.SSHConnection); err != nil {
		return Result{}, err
	}
	if err := validateAdminUser(config.AdminUser); err != nil {
		return Result{}, err
	}
	store, err := localstate.Open(config.StateRoot)
	if err != nil {
		return Result{}, err
	}
	artifactsDir, err := store.EnsureDir("apply/artifacts")
	if err != nil {
		return Result{}, err
	}
	stagingDir, err := store.EnsureDir("apply/staging")
	if err != nil {
		return Result{}, err
	}
	logsDir, err := store.EnsureDir("apply/logs")
	if err != nil {
		return Result{}, err
	}
	runtimeRecoveryDir, err := store.EnsureDir("apply/runtime-recovery")
	if err != nil {
		return Result{}, err
	}
	applyLock, err := acquireTargetApplyLock(filepath.Join(config.StateRoot, "apply", "targetapply.lock"))
	if err != nil {
		return Result{}, err
	}
	defer releaseTargetApplyLock(applyLock)
	if err := cleanupManagedStaging(stagingDir); err != nil {
		return Result{}, err
	}
	current, personaID, err := loadFullCheckpoint(store)
	if err != nil {
		return Result{}, err
	}
	if err := rejectRollback(current, config.Plan); err != nil {
		return Result{}, err
	}
	if personaID != "" {
		actual, readErr := readPersonaID()
		if readErr != nil || actual != personaID {
			return Result{}, ErrPersonaChanged
		}
	} else if config.Plan.Profile == "pbp" {
		actual, exists, readErr := readPersonaIDIfPresent()
		if readErr != nil {
			return Result{}, readErr
		}
		if exists {
			// A persona created before the first target checkpoint is already
			// stable and must not be silently replaced by this installation.
			personaID = actual
		}
	}
	r := &runner{config: config, store: store, artifactsDir: artifactsDir, runtimeRecoveryDir: runtimeRecoveryDir, stagingDir: stagingDir, logsDir: logsDir, logPaths: map[string]string{}}
	handoff, err := r.prepareRuntimeHandoff(ctx)
	if err != nil {
		return Result{PlanID: config.Plan.ID, LogPaths: r.logPaths}, err
	}
	if handoff {
		// No profile phase or checkpoint may be written by the old executable.
		return Result{PlanID: config.Plan.ID, HandoffRequired: true, LogPaths: r.logPaths}, nil
	}
	enginePlan := reconcile.Plan{
		Instance: config.Plan.Instance, Profile: config.Plan.Profile,
		ReleaseSet: config.Plan.ReleaseSet, Generation: config.Plan.DesiredGeneration,
		PlanID: config.Plan.ID,
	}
	for _, phase := range config.Plan.Phases {
		enginePlan.Phases = append(enginePlan.Phases, phase.Profile)
	}
	engine := reconcile.Engine{
		StateDirectory: filepath.Join(config.StateRoot, "apply"), Runner: r, Now: config.Now,
		Event: func(event reconcile.Event) {
			if config.Event != nil {
				config.Event(event.Phase, event.Status, event.Detail)
			}
		},
	}
	journal, err := engine.Run(ctx, enginePlan)
	if err != nil {
		return Result{PlanID: config.Plan.ID, Journal: journal, LogPaths: r.logPaths}, err
	}
	if config.Plan.Profile == "pbp" {
		actual, readErr := readPersonaID()
		if readErr != nil {
			return Result{PlanID: config.Plan.ID, Journal: journal, LogPaths: r.logPaths}, readErr
		}
		if personaID != "" && actual != personaID {
			return Result{PlanID: config.Plan.ID, Journal: journal, LogPaths: r.logPaths}, ErrPersonaChanged
		}
		personaID = actual
	}
	checkpoint := Checkpoint{
		Schema: checkpointSchema, ReleaseGeneration: config.Plan.ReleaseGeneration,
		ReleaseSet: config.Plan.ReleaseSet, DesiredGeneration: config.Plan.DesiredGeneration,
		DesiredStateID: config.Plan.DesiredStateID, PlanID: config.Plan.ID,
		PersonaID: personaID, AppliedAt: config.Now().UTC().Unix(),
	}
	if err := store.WriteJSON("apply/checkpoint.json", checkpoint); err != nil {
		return Result{PlanID: config.Plan.ID, Journal: journal, LogPaths: r.logPaths}, err
	}
	return Result{PlanID: config.Plan.ID, Checkpoint: checkpoint, Journal: journal, LogPaths: r.logPaths}, nil
}

func validatePlan(plan applyplan.Plan) error {
	runtimeTarget, runtimeErr := RuntimeTarget()
	if plan.Schema != applyplan.SchemaVersion || !identifierRE.MatchString(plan.Instance) ||
		plan.Profile == "" || runtimeErr != nil || plan.Target != runtimeTarget ||
		plan.ID == "" || !digestRE.MatchString(plan.ID) ||
		!digestRE.MatchString(plan.ReleaseSet) || !digestRE.MatchString(plan.DesiredStateID) ||
		plan.ReleaseGeneration == 0 || plan.DesiredGeneration == 0 || len(plan.AuthorizedSSHKeys) == 0 ||
		len(plan.AuthorizedSSHKeys) > 32 || len(plan.Phases) == 0 {
		return ErrInvalidConfig
	}
	for index, key := range plan.AuthorizedSSHKeys {
		if !validOpenSSHEd25519(key) || index > 0 && plan.AuthorizedSSHKeys[index-1] >= key {
			return ErrInvalidConfig
		}
	}
	copy := plan
	copy.ID = ""
	canonical, err := signing.CanonicalJSON(copy)
	if err != nil {
		return ErrInvalidConfig
	}
	hash := sha256.Sum256(canonical)
	if plan.ID != "sha256:"+hex.EncodeToString(hash[:]) {
		return ErrInvalidConfig
	}
	wantPhases := map[string][]string{
		"ssh":     {"flow", "ssh"},
		"ssh-gui": {"flow", "ssh", "ssh-gui"},
		"vpn":     {"flow", "ssh", "vpn"},
		"pbp":     {"flow", "ssh", "ssh-gui", "vpn-pbp-de", "pbp"},
	}
	wanted, supported := wantPhases[plan.Profile]
	if !supported || len(plan.Phases) != len(wanted) {
		return ErrUnsupportedProfile
	}
	wantComponent := map[string]string{"flow": "flow", "ssh": "ssh", "ssh-gui": "ssh", "vpn": "vpn", "vpn-pbp-de": "vpn", "pbp": "pbp"}
	wantDependencies := map[string][]string{
		"flow": nil, "ssh": {"phase/flow"}, "ssh-gui": {"phase/ssh"}, "vpn": {"phase/ssh"},
		"vpn-pbp-de": {"phase/ssh-gui"}, "pbp": {"phase/vpn-pbp-de"},
	}
	seenSteps := map[string]bool{}
	for index, phase := range plan.Phases {
		if phase.Profile != wanted[index] || len(phase.Steps) != 1 || phase.ID != "phase/"+phase.Profile ||
			!equalStrings(phase.DependsOn, wantDependencies[phase.Profile]) {
			return ErrInvalidConfig
		}
		for _, step := range phase.Steps {
			if seenSteps[step.ID] || step.ID != phase.ID+"/component/"+wantComponent[phase.Profile] ||
				step.Artifact.Component != wantComponent[phase.Profile] || !digestRE.MatchString(step.Artifact.Digest) ||
				step.Artifact.Size <= 0 || step.Artifact.Size > maxArtifactSize ||
				(step.Artifact.Target != "any" && step.Artifact.Target != plan.Target) ||
				!validArtifactPath(step.Artifact) {
				return ErrInvalidConfig
			}
			if phase.Profile == "flow" && (step.Artifact.Size > maxRuntimeArtifactSize ||
				step.Artifact.Target != plan.Target ||
				step.Artifact.Path != "flow/"+step.Artifact.Version+"/"+plan.Target+"/flow") {
				return ErrInvalidConfig
			}
			seenSteps[step.ID] = true
		}
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validArtifactPath(artifact applyplan.Artifact) bool {
	if !safeNameRE.MatchString(artifact.Component) || !versionRE.MatchString(artifact.Version) ||
		!safeNameRE.MatchString(artifact.Target) || artifact.Path == "" || filepath.IsAbs(artifact.Path) ||
		strings.ContainsRune(artifact.Path, '\x00') || filepath.ToSlash(filepath.Clean(artifact.Path)) != artifact.Path {
		return false
	}
	parts := strings.Split(artifact.Path, "/")
	return len(parts) == 4 && parts[0] == artifact.Component && parts[1] == artifact.Version &&
		parts[2] == artifact.Target && safeNameRE.MatchString(parts[3])
}

func validOpenSSHEd25519(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "ssh-ed25519" || strings.Join(fields, " ") != line || len(line) > 8192 {
		return false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return false
	}
	reader := bytes.NewReader(blob)
	algorithm, ok := readSSHString(reader)
	if !ok || string(algorithm) != "ssh-ed25519" {
		return false
	}
	key, ok := readSSHString(reader)
	return ok && len(key) == 32 && reader.Len() == 0
}

func readSSHString(reader *bytes.Reader) ([]byte, bool) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil || size > uint32(reader.Len()) {
		return nil, false
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(reader, value); err != nil {
		return nil, false
	}
	return value, true
}

func validateAdminUser(name string) error {
	account, err := user.Lookup(name)
	if err != nil {
		return fmt.Errorf("%w: admin user does not exist", ErrInvalidConfig)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid < 1000 || !filepath.IsAbs(account.HomeDir) || account.HomeDir == "/" {
		return fmt.Errorf("%w: unsafe admin user", ErrInvalidConfig)
	}
	info, err := os.Lstat(account.HomeDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: unsafe admin home", ErrInvalidConfig)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: unsafe admin home ownership", ErrInvalidConfig)
	}
	return nil
}

// ValidateAdminUser verifies the fixed target administrator policy without
// modifying the account. Runtime enrollment uses the same policy before it
// persists the immutable instance binding.
func ValidateAdminUser(name string) error { return validateAdminUser(name) }

func validateSSHConnection(value string) error {
	if value == "" {
		return nil
	}
	fields := strings.Fields(value)
	if len(fields) != 4 || net.ParseIP(fields[0]) == nil || net.ParseIP(fields[0]).To4() == nil ||
		net.ParseIP(fields[2]) == nil || net.ParseIP(fields[2]).To4() == nil {
		return fmt.Errorf("%w: only a direct IPv4 SSH connection may be propagated", ErrInvalidConfig)
	}
	for _, index := range []int{1, 3} {
		port, err := strconv.Atoi(fields[index])
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("%w: invalid SSH connection", ErrInvalidConfig)
		}
	}
	return nil
}

func rejectRollback(current Checkpoint, plan applyplan.Plan) error {
	if current.DesiredGeneration > plan.DesiredGeneration || current.ReleaseGeneration > plan.ReleaseGeneration ||
		current.DesiredGeneration == plan.DesiredGeneration && current.DesiredGeneration != 0 && current.DesiredStateID != plan.DesiredStateID ||
		current.ReleaseGeneration == plan.ReleaseGeneration && current.ReleaseGeneration != 0 && current.ReleaseSet != plan.ReleaseSet {
		return applyplan.ErrRollback
	}
	return nil
}

func validateCheckpoint(checkpoint Checkpoint) error {
	if checkpoint.Schema != checkpointSchema || checkpoint.ReleaseGeneration == 0 ||
		checkpoint.DesiredGeneration == 0 || checkpoint.AppliedAt <= 0 ||
		!digestRE.MatchString(checkpoint.ReleaseSet) || !digestRE.MatchString(checkpoint.DesiredStateID) ||
		!digestRE.MatchString(checkpoint.PlanID) || (checkpoint.PersonaID != "" && !personaRE.MatchString(checkpoint.PersonaID)) {
		return ErrInvalidConfig
	}
	return nil
}

func loadFullCheckpoint(store *localstate.Store) (Checkpoint, string, error) {
	var checkpoint Checkpoint
	if err := store.ReadJSON("apply/checkpoint.json", &checkpoint); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Checkpoint{}, "", nil
		}
		return Checkpoint{}, "", err
	}
	if err := validateCheckpoint(checkpoint); err != nil {
		return Checkpoint{}, "", err
	}
	return checkpoint, checkpoint.PersonaID, nil
}

func acquireTargetApplyLock(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			return nil, errors.New("unsafe target apply lock")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("open target apply lock")
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		int(details.Uid) != os.Geteuid() || details.Nlink != 1 {
		file.Close()
		return nil, errors.New("unsafe target apply lock")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, reconcile.ErrBusy
		}
		return nil, err
	}
	return file, nil
}

func releaseTargetApplyLock(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func cleanupManagedStaging(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	prefixes := []string{".authorized-key-", ".ssh-", ".ssh-gui-", ".vpn-", ".vpn-pbp-de-", ".pbp-"}
	for _, entry := range entries {
		managed := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(entry.Name(), prefix) {
				managed = true
				break
			}
		}
		if !managed {
			return errors.New("unrecognized target apply staging entry")
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		} else if info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(path); err != nil {
				return err
			}
		} else {
			return errors.New("unsafe target apply staging entry")
		}
	}
	return syncDirectory(directory)
}

func (r *runner) phase(name string) (applyplan.Phase, error) {
	for _, phase := range r.config.Plan.Phases {
		if phase.Profile == name {
			return phase, nil
		}
	}
	return applyplan.Phase{}, ErrInvalidConfig
}

func (r *runner) Preflight(ctx context.Context, name string, _ reconcile.Plan) error {
	phase, err := r.phase(name)
	if err != nil {
		return err
	}
	if name == "flow" {
		if _, err := r.ensureRuntimeArtifact(ctx, phase.Steps[0].Artifact); err != nil {
			return &reconcile.PhaseError{Code: "runtime_artifact_verification", Message: "the signed flow runtime could not be verified", Next: "check serving release health and retry; the installed runtime was not changed"}
		}
		return nil
	}
	for _, step := range phase.Steps {
		if _, err := r.ensureArtifact(ctx, step.Artifact); err != nil {
			return &reconcile.PhaseError{Code: "artifact_verification", Message: "the signed component artifact could not be verified", Next: "check serving release health and retry"}
		}
	}
	return nil
}

func (r *runner) Apply(ctx context.Context, name string, _ reconcile.Plan) error {
	phase, err := r.phase(name)
	if err != nil {
		return err
	}
	if name == "flow" {
		if err := r.activateRuntimeArtifact(ctx, phase.Steps[0].Artifact); err != nil {
			return &reconcile.PhaseError{Code: "runtime_activation_failed", Message: "the verified flow runtime could not be activated atomically", Next: "retry; use the digest-named root-only recovery copy for console recovery"}
		}
		return nil
	}
	if name == "ssh" || name == "ssh-gui" {
		if err := r.activateAuthorizedSSHKeys(); err != nil {
			return &reconcile.PhaseError{Code: "authorized_keys_activation_failed", Message: "the complete signed SSH key set could not be activated atomically", Next: "inspect home and .ssh ownership, modes, symlinks and hardlinks, then retry"}
		}
	}
	for _, step := range phase.Steps {
		archive, err := r.ensureArtifact(ctx, step.Artifact)
		if err != nil {
			return err
		}
		root, cleanup, err := r.extract(name, archive)
		if err != nil {
			return err
		}
		err = r.runFixedInstaller(ctx, name, root)
		cleanup()
		if err != nil {
			return &reconcile.PhaseError{Code: "installer_failed", Message: "the fixed profile installer failed; details are in its protected log", Next: "inspect flow instance logs and the target root-only component log, then retry"}
		}
	}
	return nil
}

func (r *runner) Verify(ctx context.Context, name string, _ reconcile.Plan) error {
	switch name {
	case "flow":
		return r.verifyRuntimeArtifact()
	case "ssh":
		accessPolicy := sshAccessCommon
		if r.config.Plan.Profile == "ssh" || r.config.Plan.Profile == "vpn" {
			accessPolicy = sshAccessClosed
		}
		return r.verifySSH(ctx, accessPolicy)
	case "ssh-gui":
		if err := r.verifySSH(ctx, sshAccessGUI); err != nil {
			return err
		}
		return verifyVNC(ctx)
	case "vpn":
		return verifyVPN(ctx, false)
	case "vpn-pbp-de":
		return verifyVPN(ctx, true)
	case "pbp":
		if err := verifyVPN(ctx, true); err != nil {
			return err
		}
		_, err := readPersonaID()
		return err
	default:
		return ErrUnsupportedProfile
	}
}

func (r *runner) Rollback(ctx context.Context, name string, _ reconcile.Plan, _ error) error {
	if name == "flow" {
		return nil
	}
	if name == "ssh-gui" {
		// A GUI verification failure can mean that VNC drifted onto a public
		// listener. Closing SSH alone would leave that listener reachable.
		if err := errors.Join(disableVNCFailClosed(ctx), disableSSHFailClosed(ctx)); err != nil {
			return err
		}
		return reconcile.ErrFailClosedEstablished
	}
	if name == "ssh" {
		if err := disableSSHFailClosed(ctx); err != nil {
			return err
		}
		return reconcile.ErrFailClosedEstablished
	}
	if name == "vpn" || name == "vpn-pbp-de" || name == "pbp" {
		if err := ensureVPNFailClosedWithBinary(ctx, "/usr/bin/mullvad", true); err == nil {
			return reconcile.ErrFailClosedEstablished
		} else {
			return err
		}
	}
	return errors.New("independent rollback could not be confirmed; leave component fail-closed")
}

// Revoke establishes the fixed local revoked state without running any
// release-provided installer: SSH is stopped and disabled, authorized_keys is
// atomically emptied, and an installed Mullvad client is confirmed in
// lockdown mode. It shares targetapply's outer lock with Run.
func Revoke(ctx context.Context, stateRoot, adminUser, profile string) error {
	if ctx == nil || !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) == "/" ||
		!userRE.MatchString(adminUser) || adminUser == "root" || adminUser == "malwarelab" ||
		(profile != "ssh" && profile != "ssh-gui" && profile != "vpn" && profile != "pbp") {
		return ErrInvalidConfig
	}
	if err := validateAdminUser(adminUser); err != nil {
		return err
	}
	store, err := localstate.Open(stateRoot)
	if err != nil {
		return err
	}
	if _, err := store.EnsureDir("apply"); err != nil {
		return err
	}
	lock, err := acquireTargetApplyLock(filepath.Join(stateRoot, "apply", "targetapply.lock"))
	if err != nil {
		return err
	}
	defer releaseTargetApplyLock(lock)
	var failures []error
	if profile == "ssh-gui" || profile == "pbp" {
		if err := disableVNCFailClosed(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	if err := disableSSHFailClosed(ctx); err != nil {
		failures = append(failures, err)
	}
	if err := clearAuthorizedKeys(adminUser); err != nil {
		failures = append(failures, err)
	}
	if err := ensureVPNFailClosed(ctx, profile == "vpn" || profile == "pbp"); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func disableSSHFailClosed(ctx context.Context) error {
	info, err := os.Lstat("/usr/bin/systemctl")
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("cannot establish SSH fail-closed state without trusted systemctl")
	}
	units := []string{"ssh.socket", "ssh.service", "sshd.service"}
	for _, unit := range units {
		_ = exec.CommandContext(ctx, "/usr/bin/systemctl", "disable", "--now", unit).Run()
	}
	for _, unit := range units {
		if exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", unit).Run() == nil ||
			exec.CommandContext(ctx, "/usr/bin/systemctl", "is-enabled", "--quiet", unit).Run() == nil {
			return errors.New("SSH revocation could not be confirmed fail-closed")
		}
	}
	return nil
}

func disableVNCFailClosed(ctx context.Context) error {
	if ctx == nil || validateTrustedExecutable("/usr/bin/systemctl") != nil || validateTrustedExecutable("/usr/bin/ss") != nil {
		return errors.New("cannot establish VNC fail-closed state without trusted systemctl and ss")
	}
	return disableVNCFailClosedWithBinaries(ctx, "/usr/bin/systemctl", "/usr/bin/ss")
}

func disableVNCFailClosedWithBinaries(ctx context.Context, systemctlPath, ssPath string) error {
	if ctx == nil || !filepath.IsAbs(systemctlPath) || !filepath.IsAbs(ssPath) {
		return ErrInvalidConfig
	}
	// Ignore the mutation result and prove the resulting state independently.
	// This keeps retries idempotent when the unit was already disabled.
	_ = exec.CommandContext(ctx, systemctlPath, "disable", "--now", vncUnit).Run()
	if exec.CommandContext(ctx, systemctlPath, "is-active", "--quiet", vncUnit).Run() == nil {
		return errors.New("VNC service remains active after fail-closed action")
	}
	if exec.CommandContext(ctx, systemctlPath, "is-enabled", "--quiet", vncUnit).Run() == nil {
		return errors.New("VNC service remains enabled after fail-closed action")
	}
	listeners, err := commandOutputBounded(ctx, maxCommandOutput, ssPath, "-H", "-ltn", "sport = :5901")
	if err != nil {
		return errors.New("VNC listener state could not be verified after fail-closed action")
	}
	if len(nonemptyLines(string(listeners))) != 0 {
		return errors.New("TCP port 5901 remains open after VNC fail-closed action")
	}
	return nil
}

func clearAuthorizedKeys(adminUser string) error {
	account, err := user.Lookup(adminUser)
	if err != nil {
		return err
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil {
		return ErrInvalidConfig
	}
	sshDirectory := filepath.Join(account.HomeDir, ".ssh")
	if _, err := os.Lstat(sshDirectory); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return replaceAuthorizedKeysWithEmpty(sshDirectory, uid, gid)
}

func replaceAuthorizedKeysWithEmpty(sshDirectory string, uid, gid int) error {
	fd, err := syscall.Open(sshDirectory, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("unsafe SSH directory during revocation")
	}
	directory := os.NewFile(uintptr(fd), sshDirectory)
	if directory == nil {
		syscall.Close(fd)
		return errors.New("open SSH directory during revocation")
	}
	defer directory.Close()
	var directoryStat syscall.Stat_t
	if err := syscall.Fstat(fd, &directoryStat); err != nil || directoryStat.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		int(directoryStat.Uid) != uid || int(directoryStat.Gid) != gid || directoryStat.Mode&0o077 != 0 {
		return errors.New("unsafe SSH directory during revocation")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporaryName := ".authorized_keys.revoked-" + hex.EncodeToString(random)
	temporaryFD, err := syscall.Openat(fd, temporaryName, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	temporary := os.NewFile(uintptr(temporaryFD), temporaryName)
	if temporary == nil {
		syscall.Close(temporaryFD)
		return errors.New("create revoked authorized_keys")
	}
	activated := false
	defer func() {
		_ = temporary.Close()
		if !activated {
			_ = syscall.Unlinkat(fd, temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if err := temporary.Chown(uid, gid); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := syscall.Renameat(fd, temporaryName, fd, "authorized_keys"); err != nil {
		return err
	}
	activated = true
	if err := directory.Sync(); err != nil {
		return err
	}
	verifiedFD, err := syscall.Openat(fd, "authorized_keys", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("revoked authorized_keys could not be verified")
	}
	defer syscall.Close(verifiedFD)
	var verified syscall.Stat_t
	if err := syscall.Fstat(verifiedFD, &verified); err != nil || verified.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		verified.Mode&0o777 != 0o600 || int(verified.Uid) != uid || int(verified.Gid) != gid ||
		verified.Nlink != 1 || verified.Size != 0 {
		return errors.New("revoked authorized_keys could not be verified")
	}
	return nil
}

func ensureVPNFailClosed(ctx context.Context, required bool) error {
	return ensureVPNFailClosedWithBinary(ctx, "/usr/bin/mullvad", required)
}

func ensureVPNFailClosedWithBinary(ctx context.Context, binary string, required bool) error {
	info, err := os.Lstat(binary)
	if errors.Is(err, os.ErrNotExist) {
		if required {
			return errors.New("required Mullvad client is missing; independent VPN fail-closed state cannot be confirmed")
		}
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("installed Mullvad client is unsafe")
	}
	if err := exec.CommandContext(ctx, binary, "auto-connect", "set", "off").Run(); err != nil {
		return errors.New("Mullvad auto-connect could not be disabled during revocation")
	}
	if err := exec.CommandContext(ctx, binary, "lockdown-mode", "set", "on").Run(); err != nil {
		return errors.New("Mullvad lockdown could not be enabled during revocation")
	}
	if err := exec.CommandContext(ctx, binary, "disconnect", "--wait").Run(); err != nil {
		return errors.New("Mullvad disconnect could not be confirmed during revocation")
	}
	autoConnect, autoErr := commandOutputBounded(ctx, maxCommandOutput, binary, "auto-connect", "get")
	lockdown, lockdownErr := commandOutputBounded(ctx, maxCommandOutput, binary, "lockdown-mode", "get")
	status, statusErr := commandOutputBounded(ctx, maxCommandOutput, binary, "status", "--json")
	if autoErr != nil || lockdownErr != nil || statusErr != nil || !mullvadSettingOff(autoConnect) ||
		!mullvadSettingOn(lockdown) || validateMullvadDisconnected(status) != nil {
		return errors.New("Mullvad fail-closed settings or disconnected status could not be confirmed during revocation")
	}
	return nil
}

func (r *runner) ensureArtifact(ctx context.Context, artifact applyplan.Artifact) (string, error) {
	if !digestRE.MatchString(artifact.Digest) || artifact.Size <= 0 || artifact.Size > maxArtifactSize {
		return "", ErrArtifactVerification
	}
	name := strings.TrimPrefix(artifact.Digest, "sha256:") + ".tar.gz"
	path := filepath.Join(r.artifactsDir, name)
	if verifyFile(path, artifact) == nil {
		return path, nil
	}
	temporary, err := os.CreateTemp(r.artifactsDir, ".download-")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return "", err
	}
	limited := &boundedWriter{writer: temporary, remaining: artifact.Size}
	err = r.config.FetchArtifact(ctx, artifact, limited)
	if syncErr := temporary.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil || limited.remaining != 0 || verifyFile(temporaryPath, artifact) != nil {
		return "", ErrArtifactVerification
	}
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return "", ErrArtifactVerification
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return "", err
	}
	if err := syncDirectory(r.artifactsDir); err != nil {
		return "", err
	}
	if err := verifyFile(path, artifact); err != nil {
		return "", ErrArtifactVerification
	}
	return path, nil
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
}

func (writer *boundedWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > writer.remaining {
		return 0, ErrArtifactVerification
	}
	count, err := writer.writer.Write(data)
	writer.remaining -= int64(count)
	return count, err
}

func verifyFile(path string, artifact applyplan.Artifact) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrArtifactVerification
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return ErrArtifactVerification
	}
	defer file.Close()
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		before.Mode&0o777 != 0o600 || before.Size != artifact.Size || int(before.Uid) != os.Geteuid() || before.Nlink != 1 {
		return ErrArtifactVerification
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(fd, &after); err != nil || after.Size != before.Size || after.Mtim != before.Mtim || after.Ctim != before.Ctim {
		return ErrArtifactVerification
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != artifact.Digest {
		return ErrArtifactVerification
	}
	return nil
}

func syncDirectory(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		syscall.Close(fd)
		return errors.New("open cache directory")
	}
	defer directory.Close()
	return directory.Sync()
}

func (r *runner) extract(phase, archive string) (string, func(), error) {
	// VPN and PBP deliberately run as the unprivileged administrator. A
	// private state-root staging tree is not traversable after runuser drops
	// privileges, so use a random root-owned runtime directory whose contents
	// remain read-only to that account. /run is root-controlled and ephemeral.
	directory, err := os.MkdirTemp("/run", ".dynamicflow-apply-"+phase+"-")
	if err != nil {
		return "", func() {}, err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		os.RemoveAll(directory)
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	root, err := reconcile.ExtractTarGz(archive, directory)
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := os.Chmod(directory, 0o711); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return root, cleanup, nil
}

func (r *runner) runFixedInstaller(ctx context.Context, phase, root string) error {
	logPath := filepath.Join(r.logsDir, phase+".log")
	log, err := openProtectedLog(logPath)
	if err != nil {
		return err
	}
	defer log.Close()
	logInfo, err := log.Stat()
	if err != nil {
		return err
	}
	logOutput := &sanitizedLogWriter{file: log, remaining: maxCommandLog - logInfo.Size()}
	r.logPaths[phase] = logPath
	var commands [][]string
	switch phase {
	case "ssh", "ssh-gui":
		mode := "ssh"
		if phase == "ssh-gui" {
			mode = "ssh-gui"
		}
		bootstrap := filepath.Join(root, "bootstrap-ssh.sh")
		keyPath, err := writeTemporaryKey(r.stagingDir, r.config.Plan.AuthorizedSSHKeys[0])
		if err != nil {
			return err
		}
		defer os.Remove(keyPath)
		commands = append(commands, []string{bootstrap, mode, "--user", r.config.AdminUser, "--public-key-file", keyPath, "--accept-lockout-risk"})
	case "vpn", "vpn-pbp-de":
		args := []string{filepath.Join(root, "bootstrap-vpn.sh"), "--return-after-install"}
		if phase == "vpn-pbp-de" {
			args = append(args, "--location", "de", "--skip-firefox")
		}
		args = append(args, r.networkModeArguments()...)
		commands = append(commands, append([]string{"@admin"}, args...))
	case "pbp":
		args := []string{filepath.Join(root, "bootstrap-pbp.sh")}
		args = append(args, r.networkModeArguments()...)
		commands = append(commands, append([]string{"@admin"}, args...))
	default:
		return ErrUnsupportedProfile
	}
	for _, fields := range commands {
		asAdmin := len(fields) > 0 && fields[0] == "@admin"
		if asAdmin {
			fields = fields[1:]
		}
		if len(fields) == 0 || !pathInside(root, fields[0]) {
			return ErrInvalidConfig
		}
		info, err := os.Lstat(fields[0])
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
			return ErrInvalidConfig
		}
		command := exec.CommandContext(ctx, fields[0], fields[1:]...)
		command.Dir = root
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
		if asAdmin {
			account, _ := user.Lookup(r.config.AdminUser)
			environment := []string{"/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + account.HomeDir, "USER=" + r.config.AdminUser, "LOGNAME=" + r.config.AdminUser, "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
			if r.config.SSHConnection != "" {
				environment = append(environment, "SSH_CONNECTION="+r.config.SSHConnection)
			}
			environment = append(environment, fields...)
			command = exec.CommandContext(ctx, "/usr/sbin/runuser", append([]string{"-u", r.config.AdminUser, "--"}, environment...)...)
			command.Dir = root
			command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
		}
		// Secrets are read by the fixed installers from their controlling TTY;
		// none are accepted in argv or environment. stdin is inherited only so
		// a console invocation retains normal terminal semantics.
		command.Stdin = os.Stdin
		command.Stdout, command.Stderr = logOutput, logOutput
		runErr := command.Run()
		flushErr := logOutput.Flush()
		if runErr != nil {
			return runErr
		}
		if flushErr != nil {
			return flushErr
		}
		if info, err := log.Stat(); err != nil || info.Size() > maxCommandLog {
			return errors.New("protected installer log exceeded limit")
		}
	}
	return log.Sync()
}

type sanitizedLogWriter struct {
	mu        sync.Mutex
	file      *os.File
	remaining int64
	line      []byte
	dropping  bool
	err       error
}

func (writer *sanitizedLogWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.err != nil {
		return 0, writer.err
	}
	for _, character := range data {
		if writer.dropping {
			if character == '\n' {
				writer.dropping = false
				writer.err = writer.writeSanitized([]byte("[output line exceeded safe limit]\n"))
			}
			continue
		}
		writer.line = append(writer.line, character)
		if len(writer.line) > maxLogLine {
			clear(writer.line)
			writer.line = writer.line[:0]
			writer.dropping = true
			continue
		}
		if character == '\n' {
			writer.err = writer.writeSanitized(writer.line)
			clear(writer.line)
			writer.line = writer.line[:0]
		}
		if writer.err != nil {
			return len(data), writer.err
		}
	}
	return len(data), nil
}

func (writer *sanitizedLogWriter) Flush() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.err != nil {
		return writer.err
	}
	if writer.dropping {
		writer.dropping = false
		writer.err = writer.writeSanitized([]byte("[output line exceeded safe limit]\n"))
	} else if len(writer.line) != 0 {
		writer.err = writer.writeSanitized(writer.line)
	}
	clear(writer.line)
	writer.line = writer.line[:0]
	return writer.err
}

func (writer *sanitizedLogWriter) writeSanitized(data []byte) error {
	cleaned := strings.Map(func(character rune) rune {
		if character == '\n' || character == '\t' || character >= 32 && character != 127 {
			return character
		}
		return ' '
	}, string(data))
	cleaned = secretLikeRE.ReplaceAllString(cleaned, "[REDACTED]")
	encoded := []byte(cleaned)
	if int64(len(encoded)) > writer.remaining {
		return errors.New("protected installer log reached its size limit")
	}
	count, err := writer.file.Write(encoded)
	writer.remaining -= int64(count)
	if err != nil {
		return err
	}
	if count != len(encoded) {
		return io.ErrShortWrite
	}
	return nil
}

func (r *runner) networkModeArguments() []string {
	if r.config.SSHConnection == "" {
		return []string{"--outbound-https-enrollment"}
	}
	return nil
}

func writeTemporaryKey(directory, value string) (string, error) {
	if !validOpenSSHEd25519(value) {
		return "", ErrInvalidConfig
	}
	file, err := os.CreateTemp(directory, ".authorized-key-")
	if err != nil {
		return "", err
	}
	path := file.Name()
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", err
	}
	_, writeErr := io.WriteString(file, value+"\n")
	if syncErr := file.Sync(); writeErr == nil {
		writeErr = syncErr
	}
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return "", writeErr
	}
	remove = false
	return path, nil
}

func openProtectedLog(path string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() > maxCommandLog {
			return nil, errors.New("unsafe or oversized protected log")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Start each attempt with a newly cleaned stream. This prevents legacy or
	// interrupted unsanitized output from being exposed through the managed
	// log path and avoids a permanently exhausted append-only log.
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("open protected log")
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 {
		file.Close()
		return nil, errors.New("unsafe protected log")
	}
	// Truncate only after fstat proves this descriptor is not a hardlink to
	// another root-owned file. O_TRUNC would mutate it before that check.
	if err := file.Truncate(0); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func pathInside(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

type sshAccessPolicy uint8

const (
	sshAccessCommon sshAccessPolicy = iota
	sshAccessClosed
	sshAccessGUI
)

func (r *runner) verifySSH(ctx context.Context, access sshAccessPolicy) error {
	if access > sshAccessGUI || validateTrustedExecutable("/usr/sbin/sshd") != nil {
		return errors.New("SSH verifier is missing or unsafe")
	}
	// Verify the current administrator context and a root context. Supplying
	// -C is essential: sshd -T without it does not evaluate Match blocks and
	// could therefore report a safe global policy while the real login context
	// permits a weaker authentication method.
	checks := []struct {
		user   string
		access sshAccessPolicy
	}{{r.config.AdminUser, access}, {"root", sshAccessCommon}}
	if access == sshAccessGUI {
		// DenyUsers can itself occur inside Match. Evaluate the untrusted GUI
		// identity instead of inferring its policy from the administrator.
		checks = append(checks, struct {
			user   string
			access sshAccessPolicy
		}{vncUser, sshAccessGUI})
	}
	for _, check := range checks {
		connectionContext, err := sshdConnectionContext(check.user, r.config.SSHConnection)
		if err != nil {
			return err
		}
		output, err := commandOutputBounded(ctx, maxCommandOutput, "/usr/sbin/sshd", "-T", "-C", connectionContext)
		if err != nil {
			return err
		}
		if err := verifySSHEffectivePolicy(output, check.access); err != nil {
			return err
		}
	}
	// The release-provided bootstrap runs after the pre-activation. Re-open the
	// account home one component at a time without following symlinks and prove
	// that the installer did not drift the complete signed key set before the
	// reconcile engine can commit this phase.
	return r.verifyAuthorizedSSHKeys()
}

func sshdConnectionContext(name, connection string) (string, error) {
	if !userRE.MatchString(name) && name != "root" {
		return "", ErrInvalidConfig
	}
	clientAddress, serverAddress, serverPort := "127.0.0.1", "127.0.0.1", "22"
	if connection != "" {
		if err := validateSSHConnection(connection); err != nil {
			return "", err
		}
		fields := strings.Fields(connection)
		clientAddress, serverAddress, serverPort = fields[0], fields[2], fields[3]
	}
	return fmt.Sprintf("user=%s,host=%s,addr=%s,laddr=%s,lport=%s", name, clientAddress, clientAddress, serverAddress, serverPort), nil
}

func verifySSHEffectivePolicy(data []byte, access sshAccessPolicy) error {
	if len(data) == 0 || int64(len(data)) > maxCommandOutput || access > sshAccessGUI {
		return errors.New("invalid effective SSH policy")
	}
	seen := map[string][]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxLogLine)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != strings.ToLower(fields[0]) {
			return errors.New("malformed effective SSH policy")
		}
		if _, duplicate := seen[fields[0]]; duplicate {
			return errors.New("duplicate effective SSH policy directive")
		}
		seen[fields[0]] = append([]string(nil), fields[1:]...)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	want := map[string]string{
		"pubkeyauthentication":         "yes",
		"authenticationmethods":        "publickey",
		"passwordauthentication":       "no",
		"kbdinteractiveauthentication": "no",
		"permitemptypasswords":         "no",
		"permitrootlogin":              "no",
		"strictmodes":                  "yes",
		"x11forwarding":                "no",
		"allowagentforwarding":         "no",
		"disableforwarding":            "no",
		"allowstreamlocalforwarding":   "no",
		"gatewayports":                 "no",
		"permittunnel":                 "no",
		"permituserrc":                 "no",
		"permituserenvironment":        "no",
		"hostbasedauthentication":      "no",
		"ignorerhosts":                 "yes",
	}
	for key, value := range want {
		if values := seen[key]; len(values) != 1 || values[0] != value {
			return fmt.Errorf("SSH policy %s is not exactly %s", key, value)
		}
	}
	authorizedKeys := seen["authorizedkeysfile"]
	foundAuthorizedKeys := false
	for _, value := range authorizedKeys {
		if value == ".ssh/authorized_keys" || value == "%h/.ssh/authorized_keys" {
			foundAuthorizedKeys = true
		}
	}
	if !foundAuthorizedKeys {
		return errors.New("SSH policy does not use the managed authorized_keys path")
	}
	switch access {
	case sshAccessCommon:
		return nil
	case sshAccessClosed:
		if values := seen["allowtcpforwarding"]; len(values) != 1 || values[0] != "no" {
			return errors.New("SSH baseline unexpectedly permits TCP forwarding")
		}
		if values := seen["permitopen"]; len(values) != 1 || values[0] != "none" {
			return errors.New("SSH baseline PermitOpen is not none")
		}
	case sshAccessGUI:
		if values := seen["allowtcpforwarding"]; len(values) != 1 || values[0] != "local" {
			return errors.New("SSH GUI policy does not restrict forwarding to local")
		}
		if values := seen["permitopen"]; len(values) != 1 || values[0] != "127.0.0.1:5901" {
			return errors.New("SSH GUI policy permits a destination other than loopback VNC")
		}
		denied := false
		for _, value := range seen["denyusers"] {
			if value == vncUser {
				denied = true
			}
		}
		if !denied {
			return errors.New("SSH GUI account is not denied direct SSH login")
		}
	}
	return nil
}

func readAuthorizedKeys(path string, uid, gid int) ([]byte, error) {
	directoryPath := filepath.Dir(path)
	directoryFD, err := syscall.Open(directoryPath, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("unsafe authorized_keys directory")
	}
	defer syscall.Close(directoryFD)
	var directory syscall.Stat_t
	if err := syscall.Fstat(directoryFD, &directory); err != nil || directory.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		int(directory.Uid) != uid || int(directory.Gid) != gid || directory.Mode&0o077 != 0 {
		return nil, errors.New("unsafe authorized_keys directory")
	}
	fd, err := syscall.Openat(directoryFD, filepath.Base(path), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("unsafe authorized_keys")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("unsafe authorized_keys")
	}
	defer file.Close()
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		details.Mode&0o777 != 0o600 || int(details.Uid) != uid || int(details.Gid) != gid ||
		details.Nlink != 1 || details.Size <= 0 || details.Size > maxAuthorizedKeys {
		return nil, errors.New("unsafe authorized_keys")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAuthorizedKeys+1))
	if err != nil || int64(len(data)) > maxAuthorizedKeys {
		return nil, errors.New("unsafe authorized_keys")
	}
	return data, nil
}

func nonemptyLines(value string) []string {
	var result []string
	for _, line := range strings.Split(value, "\n") {
		if strings.TrimSpace(line) != "" {
			result = append(result, strings.TrimSpace(line))
		}
	}
	return result
}

func verifyVNC(ctx context.Context) error {
	for _, path := range []string{
		"/usr/bin/systemctl", "/usr/bin/ss", "/usr/bin/passwd", "/usr/bin/id",
		"/usr/bin/pgrep", "/usr/sbin/runuser", "/usr/bin/env", "/usr/bin/tigervncconfig",
	} {
		if err := validateTrustedExecutable(path); err != nil {
			return errors.New("VNC verifier dependency is missing or unsafe")
		}
	}
	account, err := user.Lookup(vncUser)
	if err != nil {
		return errors.New("managed VNC account is missing")
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil || uid < 1000 || gid < 0 || account.HomeDir == "" ||
		!filepath.IsAbs(account.HomeDir) || filepath.Clean(account.HomeDir) != account.HomeDir || account.HomeDir == "/" {
		return errors.New("managed VNC account is unsafe")
	}
	homeInfo, err := os.Lstat(account.HomeDir)
	homeStat, homeStatOK := fileStat(homeInfo)
	if err != nil || !homeInfo.IsDir() || homeInfo.Mode()&os.ModeSymlink != 0 || homeInfo.Mode().Perm()&0o022 != 0 ||
		!homeStatOK || int(homeStat.Uid) != uid {
		return errors.New("managed VNC home is unsafe")
	}
	marker, err := readProtectedEvidence(vncAccountMarker, 0o600, 0, -1, 256)
	if err != nil {
		return errors.New("managed VNC account marker is missing or unsafe")
	}
	passwordStatus, err := commandOutputBounded(ctx, 4096, "/usr/bin/passwd", "--status", vncUser)
	if err != nil {
		return errors.New("managed VNC password lock could not be verified")
	}
	groups, err := commandOutputBounded(ctx, 4096, "/usr/bin/id", "-nG", vncUser)
	if err != nil {
		return errors.New("managed VNC group membership could not be verified")
	}
	if err := validateManagedVNCAccountEvidence(uid, marker, passwordStatus, groups); err != nil {
		return err
	}
	if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", vncUnit).Run(); err != nil {
		return err
	}
	output, err := commandOutputBounded(ctx, maxCommandOutput, "/usr/bin/ss", "-H", "-ltn", "sport = :5901")
	if err != nil {
		return err
	}
	seenIPv4 := false
	for _, line := range nonemptyLines(string(output)) {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return errors.New("malformed VNC listener")
		}
		address := fields[3]
		switch address {
		case "127.0.0.1:5901":
			seenIPv4 = true
		case "[::1]:5901", "::1:5901":
		default:
			return errors.New("VNC is not loopback-only")
		}
	}
	if !seenIPv4 {
		return errors.New("VNC IPv4 loopback listener missing")
	}
	values := make(map[string]string, 10)
	for _, parameter := range []string{
		"PasswordFile", "SecurityTypes", "localhost", "rfbport", "AlwaysShared", "NeverShared",
		"AllowOverride", "AcceptCutText", "SendCutText", "SendPrimary", "SetPrimary",
	} {
		value, err := queryVNCRuntimeValue(ctx, account, parameter)
		if err != nil {
			return fmt.Errorf("VNC runtime policy %s could not be verified", parameter)
		}
		values[parameter] = value
	}
	if err := validateVNCRuntimePolicy(values); err != nil {
		return err
	}
	wantPasswordPaths := []string{
		filepath.Join(account.HomeDir, ".vnc", "passwd"),
		filepath.Join(account.HomeDir, ".config", "tigervnc", "passwd"),
	}
	if values["PasswordFile"] != wantPasswordPaths[0] && values["PasswordFile"] != wantPasswordPaths[1] {
		return errors.New("VNC runtime uses an unmanaged password file")
	}
	firstPassword, err := readProtectedEvidence(wantPasswordPaths[0], 0o600, uid, gid, 64)
	if err != nil {
		return errors.New("managed VNC password file is missing or unsafe")
	}
	secondPassword, err := readProtectedEvidence(wantPasswordPaths[1], 0o600, uid, gid, 64)
	if err != nil || len(firstPassword) != 8 || !bytes.Equal(firstPassword, secondPassword) {
		return errors.New("managed VNC password files differ or are unsafe")
	}
	if _, err := readProtectedEvidence(filepath.Join(account.HomeDir, ".Xauthority"), 0o600, uid, gid, 1<<20); err != nil {
		return errors.New("VNC Xauthority is missing or unsafe")
	}
	for _, process := range []string{"Xtigervnc", "xfce4-session", "xfwm4", "xfce4-panel", "xfdesktop"} {
		if err := exec.CommandContext(ctx, "/usr/bin/pgrep", "-u", strconv.Itoa(uid), "-x", process).Run(); err != nil {
			return fmt.Errorf("managed GUI process %s is not running as malwarelab", process)
		}
	}
	info, err := os.Lstat(vncSecretPath)
	stat, statOK := fileStat(info)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		!statOK || stat.Uid != 0 || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > 4096 {
		return errors.New("VNC secret is missing or unsafe")
	}
	return nil
}

func validateTrustedExecutable(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("trusted executable path is not absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("trusted executable is unsafe")
	}
	stat, ok := fileStat(info)
	if !ok || int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 {
		return errors.New("trusted executable ownership is unsafe")
	}
	return nil
}

func readProtectedEvidence(path string, mode os.FileMode, uid, gid int, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || limit <= 0 {
		return nil, ErrInvalidConfig
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("open protected evidence")
	}
	defer file.Close()
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		before.Mode&0o777 != uint32(mode.Perm()) || int(before.Uid) != uid || before.Nlink != 1 ||
		(gid >= 0 && int(before.Gid) != gid) || before.Size <= 0 || before.Size > limit {
		return nil, errors.New("protected evidence metadata is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("protected evidence is oversized")
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(fd, &after); err != nil || after.Ino != before.Ino || after.Size != before.Size ||
		after.Mtim != before.Mtim || after.Ctim != before.Ctim {
		return nil, errors.New("protected evidence changed while reading")
	}
	return data, nil
}

func validateManagedVNCAccountEvidence(uid int, marker, passwordStatus, groups []byte) error {
	if uid < 1000 || string(marker) != fmt.Sprintf("%s:%d\n", vncUser, uid) {
		return errors.New("managed VNC account identity marker changed")
	}
	statusFields := strings.Fields(string(passwordStatus))
	if len(statusFields) < 2 || statusFields[0] != vncUser || statusFields[1] != "L" {
		return errors.New("managed VNC account password is not locked")
	}
	privileged := map[string]bool{
		"sudo": true, "wheel": true, "docker": true, "lxd": true, "incus": true,
		"incus-admin": true, "libvirt": true, "disk": true, "kvm": true,
	}
	for _, group := range strings.Fields(string(groups)) {
		if privileged[group] {
			return fmt.Errorf("managed VNC account belongs to privileged group %s", group)
		}
	}
	return nil
}

func queryVNCRuntimeValue(ctx context.Context, account *user.User, parameter string) (string, error) {
	allowed := map[string]bool{
		"PasswordFile": true, "SecurityTypes": true, "localhost": true, "rfbport": true,
		"AlwaysShared": true, "NeverShared": true, "AllowOverride": true,
		"AcceptCutText": true, "SendCutText": true, "SendPrimary": true, "SetPrimary": true,
	}
	if account == nil || account.Username != vncUser || !allowed[parameter] {
		return "", ErrInvalidConfig
	}
	output, err := commandOutputBounded(ctx, 4096, "/usr/sbin/runuser",
		"-u", vncUser, "--", "/usr/bin/env", "-i",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME="+account.HomeDir, "USER="+vncUser, "LOGNAME="+vncUser,
		"DISPLAY=:"+vncDisplay, "XAUTHORITY="+filepath.Join(account.HomeDir, ".Xauthority"),
		"/usr/bin/tigervncconfig", "-get", parameter,
	)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(output))
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("invalid VNC runtime value")
	}
	return value, nil
}

func validateVNCRuntimePolicy(values map[string]string) error {
	if values["SecurityTypes"] != "VncAuth" || values["rfbport"] != vncPort ||
		values["AllowOverride"] != "desktop,AcceptPointerEvents" {
		return errors.New("VNC authentication, port, or override policy drifted")
	}
	for _, parameter := range []string{"localhost", "NeverShared"} {
		if value, ok := parseVNCBool(values[parameter]); !ok || !value {
			return fmt.Errorf("VNC runtime %s is not enabled", parameter)
		}
	}
	for _, parameter := range []string{"AlwaysShared", "AcceptCutText", "SendCutText", "SendPrimary", "SetPrimary"} {
		if value, ok := parseVNCBool(values[parameter]); !ok || value {
			return fmt.Errorf("VNC runtime %s is not disabled", parameter)
		}
	}
	return nil
}

func parseVNCBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "on", "yes", "true":
		return true, true
	case "0", "off", "no", "false":
		return false, true
	default:
		return false, false
	}
}

func verifyVPN(ctx context.Context, requireGermany bool) error {
	status, err := mullvadOutput(ctx, "status", "--json")
	if err != nil {
		return errors.New("Mullvad status is temporarily unavailable")
	}
	if err := validateMullvadStatus(status, requireGermany); err != nil {
		return err
	}
	if requireGermany {
		settings, settingsErr := mullvadOutput(ctx, "anti-censorship", "get")
		autoConnect, autoErr := mullvadOutput(ctx, "auto-connect", "get")
		lockdown, lockdownErr := mullvadOutput(ctx, "lockdown-mode", "get")
		if settingsErr != nil || autoErr != nil || lockdownErr != nil {
			return errors.New("Mullvad PBP transport policy is temporarily unavailable")
		}
		if err := validatePBPTransportSettings(settings, autoConnect, lockdown); err != nil {
			return err
		}
	}
	var lastTransient error
	for attempt := 0; attempt < 4; attempt++ {
		check, err := commandOutputBounded(ctx, maxCommandOutput, "/usr/bin/curl", "-4", "--disable", "--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2", "--connect-timeout", "10", "--max-time", "30", "https://am.i.mullvad.net/json")
		if err == nil {
			err = validateMullvadEgress(check, requireGermany)
			if err == nil {
				return nil
			}
			if errors.Is(err, errDefinitiveVPNPolicy) {
				return err
			}
		}
		lastTransient = err
		if attempt == 3 {
			break
		}
		delay := time.Duration(1<<attempt) * time.Second
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("Mullvad egress verification remained unavailable after bounded retries: %w", lastTransient)
}

var errDefinitiveVPNPolicy = errors.New("definitive Mullvad policy failure")

type mullvadStatus struct {
	State   string `json:"state"`
	Details struct {
		Endpoint struct {
			Obfuscation struct {
				Single struct {
					Type     string `json:"obfuscation_type"`
					Endpoint struct {
						Address string `json:"address"`
					} `json:"endpoint"`
				} `json:"Single"`
			} `json:"obfuscation"`
		} `json:"endpoint"`
	} `json:"details"`
}

func mullvadOutput(ctx context.Context, arguments ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return commandOutputBounded(bounded, maxCommandOutput, "/usr/bin/mullvad", arguments...)
}

func validateMullvadStatus(data []byte, requirePBP bool) error {
	var status mullvadStatus
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&status); err != nil {
		return errors.New("invalid Mullvad status response")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("invalid Mullvad status response")
	}
	if status.State != "connected" {
		return fmt.Errorf("%w: Mullvad is not connected", errDefinitiveVPNPolicy)
	}
	if !requirePBP {
		return nil
	}
	if status.Details.Endpoint.Obfuscation.Single.Type != "Shadowsocks" {
		return fmt.Errorf("%w: PBP requires active Mullvad Shadowsocks", errDefinitiveVPNPolicy)
	}
	_, port, err := net.SplitHostPort(status.Details.Endpoint.Obfuscation.Single.Endpoint.Address)
	if err != nil || port != "443" {
		return fmt.Errorf("%w: PBP requires active Mullvad Shadowsocks port 443", errDefinitiveVPNPolicy)
	}
	return nil
}

func validatePBPTransportSettings(settings, autoConnect, lockdown []byte) error {
	want := map[string]bool{
		"mode: shadowsocks":              false,
		"shadowsocks settings: port 443": false,
	}
	for _, line := range nonemptyLines(string(settings)) {
		if _, ok := want[strings.ToLower(strings.TrimSpace(line))]; ok {
			want[strings.ToLower(strings.TrimSpace(line))] = true
		}
	}
	for _, present := range want {
		if !present {
			return fmt.Errorf("%w: Mullvad Shadowsocks 443 setting drifted", errDefinitiveVPNPolicy)
		}
	}
	if !mullvadSettingOn(autoConnect) {
		return fmt.Errorf("%w: Mullvad auto-connect is disabled", errDefinitiveVPNPolicy)
	}
	if !mullvadSettingOn(lockdown) {
		return fmt.Errorf("%w: Mullvad lockdown is disabled", errDefinitiveVPNPolicy)
	}
	return nil
}

func mullvadSettingOn(value []byte) bool {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(string(value))))
	return len(fields) > 0 && strings.Trim(fields[len(fields)-1], ":") == "on"
}

func mullvadSettingOff(value []byte) bool {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(string(value))))
	return len(fields) > 0 && strings.Trim(fields[len(fields)-1], ":") == "off"
}

func validateMullvadDisconnected(data []byte) error {
	var status struct {
		State string `json:"state"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&status); err != nil || status.State != "disconnected" {
		return errors.New("Mullvad is not disconnected")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("invalid Mullvad disconnected status")
	}
	return nil
}

func validateMullvadEgress(data []byte, requireGermany bool) error {
	var egress struct {
		Mullvad bool   `json:"mullvad_exit_ip"`
		Country string `json:"country"`
		IP      string `json:"ip"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&egress); err != nil {
		return errors.New("invalid Mullvad egress response")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("invalid Mullvad egress response")
	}
	address := net.ParseIP(egress.IP)
	if !egress.Mullvad || requireGermany && egress.Country != "Germany" || address == nil || address.To4() == nil || !address.IsGlobalUnicast() {
		return fmt.Errorf("%w: Mullvad egress policy failed", errDefinitiveVPNPolicy)
	}
	return nil
}

func readPersonaID() (string, error) {
	return readPersonaIDAt("/etc/toolkit/pbp-persona.json")
}

func readPersonaIDIfPresent() (string, bool, error) {
	path := "/etc/toolkit/pbp-persona.json"
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	} else if err != nil {
		return "", false, err
	}
	value, err := readPersonaIDAt(path)
	return value, err == nil, err
}

func readPersonaIDAt(path string) (string, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", errors.New("PBP persona is missing or unsafe")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		syscall.Close(fd)
		return "", errors.New("PBP persona is missing or unsafe")
	}
	defer file.Close()
	var details syscall.Stat_t
	if err := syscall.Fstat(fd, &details); err != nil || details.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		details.Mode&0o777 != 0o644 || details.Uid != 0 || details.Nlink != 1 || details.Size <= 0 || details.Size > 2<<20 {
		return "", errors.New("PBP persona is missing or unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, 2<<20+1))
	if err != nil || len(data) > 2<<20 {
		return "", errors.New("PBP persona is missing or unsafe")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return "", errors.New("PBP persona identity is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return "", errors.New("PBP persona identity is invalid")
	}
	wantKeys := []string{
		"browser_major", "browser_version", "camoufox_package_version", "config", "firefox_user_prefs",
		"locale", "os", "persona_id", "preset", "schema", "timezone",
	}
	if len(value) != len(wantKeys) {
		return "", errors.New("PBP persona identity is invalid")
	}
	for _, key := range wantKeys {
		if _, exists := value[key]; !exists {
			return "", errors.New("PBP persona identity is invalid")
		}
	}
	schema, schemaOK := value["schema"].(json.Number)
	personaID, idOK := value["persona_id"].(string)
	if !schemaOK || schema.String() != "2" || !idOK || !personaRE.MatchString(personaID) {
		return "", errors.New("PBP persona identity is invalid")
	}
	delete(value, "persona_id")
	canonical, err := canonicalPersonaJSON(value)
	if err != nil {
		return "", errors.New("PBP persona identity is invalid")
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != personaID {
		return "", errors.New("PBP persona identity hash is invalid")
	}
	return personaID, nil
}

// canonicalPersonaJSON matches Python json.dumps(sort_keys=True,
// separators=(",", ":"), ensure_ascii=True), which is the on-disk PBP
// persona identity contract. It is deliberately local to PBP because release
// signing uses a different, integer-only canonical JSON subset.
func canonicalPersonaJSON(value any) ([]byte, error) {
	var output bytes.Buffer
	if err := writeCanonicalPersonaJSON(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeCanonicalPersonaJSON(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case string:
		writePersonaJSONString(output, typed)
	case json.Number:
		if !jsonNumberRE.MatchString(typed.String()) {
			return errors.New("invalid persona number")
		}
		output.WriteString(typed.String())
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index != 0 {
				output.WriteByte(',')
			}
			if err := writeCanonicalPersonaJSON(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index != 0 {
				output.WriteByte(',')
			}
			writePersonaJSONString(output, key)
			output.WriteByte(':')
			if err := writeCanonicalPersonaJSON(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return errors.New("unsupported persona JSON value")
	}
	return nil
}

func writePersonaJSONString(output *bytes.Buffer, value string) {
	const hexDigits = "0123456789abcdef"
	output.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			output.WriteByte('\\')
			output.WriteRune(character)
		case '\b':
			output.WriteString(`\b`)
		case '\f':
			output.WriteString(`\f`)
		case '\n':
			output.WriteString(`\n`)
		case '\r':
			output.WriteString(`\r`)
		case '\t':
			output.WriteString(`\t`)
		default:
			switch {
			case character >= 0x20 && character <= 0x7e:
				output.WriteRune(character)
			case character <= 0xffff:
				output.WriteString(`\u`)
				for shift := 12; shift >= 0; shift -= 4 {
					output.WriteByte(hexDigits[uint32(character)>>shift&0xf])
				}
			default:
				code := uint32(character) - 0x10000
				for _, surrogate := range []uint32{0xd800 + code>>10, 0xdc00 + code&0x3ff} {
					output.WriteString(`\u`)
					for shift := 12; shift >= 0; shift -= 4 {
						output.WriteByte(hexDigits[surrogate>>shift&0xf])
					}
				}
			}
		}
	}
	output.WriteByte('"')
}

func fileStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

type boundedOutputBuffer struct {
	buffer bytes.Buffer
	limit  int64
}

func (output *boundedOutputBuffer) Write(data []byte) (int, error) {
	if int64(len(data)) > output.limit-int64(output.buffer.Len()) {
		return 0, errors.New("command output exceeded safe limit")
	}
	return output.buffer.Write(data)
}

func commandOutputBounded(ctx context.Context, limit int64, path string, arguments ...string) ([]byte, error) {
	if limit <= 0 || !filepath.IsAbs(path) {
		return nil, ErrInvalidConfig
	}
	output := &boundedOutputBuffer{limit: limit}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, err
	}
	return output.buffer.Bytes(), nil
}

// RuntimeTarget returns the only release targets accepted by this binary.
func RuntimeTarget() (string, error) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return "", ErrInvalidConfig
	}
	return "linux-" + runtime.GOARCH, nil
}

// CanonicalCheckpoint is exposed for black-box contract tests and diagnostics.
func CanonicalCheckpoint(checkpoint Checkpoint) ([]byte, error) {
	if err := validateCheckpoint(checkpoint); err != nil {
		return nil, err
	}
	return signing.CanonicalJSON(checkpoint)
}
