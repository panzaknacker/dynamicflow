package lab

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"
)

const MaximumForensicsBytes = 1 << 20

var forensicSHA256RE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var forensicStateRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
var forensicUTCRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

type PBPForensicsEvidence struct {
	Schema         int                    `json:"schema"`
	Test           string                 `json:"test"`
	Status         string                 `json:"status"`
	StartedAt      string                 `json:"started_at"`
	CollectedAt    string                 `json:"collected_at"`
	Desktop        PBPForensicsDesktop    `json:"desktop"`
	Profile        PBPForensicsProfile    `json:"profile"`
	Persona        PBPForensicsPersona    `json:"persona"`
	RuntimeLogs    PBPForensicsRuntimeLog `json:"runtime_logs"`
	AppArmorDenied PBPForensicsFinding    `json:"apparmor_denied"`
	KernelOOM      PBPForensicsFinding    `json:"kernel_oom"`
	KernelSegfault PBPForensicsFinding    `json:"kernel_segfault"`
	KernelKilled   PBPForensicsFinding    `json:"kernel_killed"`
	Coredumps      PBPForensicsFinding    `json:"coredumps"`
	SystemdUnits   PBPForensicsUnits      `json:"systemd_units"`
}

type PBPForensicsDesktop struct {
	XFCEActive      bool `json:"xfce_active"`
	DisplayBound    bool `json:"display_bound"`
	XAuthorityBound bool `json:"xauthority_bound"`
	VNCUnitActive   bool `json:"vnc_unit_active"`
	VNCLoopback5901 bool `json:"vnc_loopback_5901"`
	VNCPublic5901   bool `json:"vnc_public_5901"`
}

type PBPForensicsProfile struct {
	ProfileProcessCount int  `json:"profile_process_count"`
	AppLockPresent      bool `json:"app_lock_present"`
	AppLockFree         bool `json:"app_lock_free"`
	NativeLockCount     int  `json:"native_lock_count"`
}

type PBPForensicsPersona struct {
	Baseline  PBPForensicsFileMetadata `json:"baseline"`
	Current   PBPForensicsFileMetadata `json:"current"`
	Unchanged bool                     `json:"unchanged"`
}

type PBPForensicsFileMetadata struct {
	SHA256 string `json:"sha256"`
	Inode  uint64 `json:"inode"`
	Size   int64  `json:"size"`
}

type PBPForensicsRuntimeLog struct {
	Count  int                       `json:"count"`
	SHA256 []string                  `json:"sha256"`
	Events PBPForensicsRuntimeEvents `json:"events"`
}

type PBPForensicsRuntimeEvents struct {
	RuntimeStderr                  int `json:"runtime_stderr"`
	RuntimeStderrCaptureError      int `json:"runtime_stderr_capture_error"`
	RuntimeStderrCaptureIncomplete int `json:"runtime_stderr_capture_incomplete"`
	LaunchEnd                      int `json:"launch_end"`
	LaunchLifecycleComplete        int `json:"launch_lifecycle_complete"`
	BrowserContextStarted          int `json:"browser_context_started"`
	BrowserContextClosed           int `json:"browser_context_closed"`
	BrowserPageOpened              int `json:"browser_page_opened"`
	BrowserPageClosed              int `json:"browser_page_closed"`
	BrowserPageCrashed             int `json:"browser_page_crashed"`
	PlaywrightDispatchFailed       int `json:"playwright_dispatch_failed"`
}

type PBPForensicsFinding struct {
	Available bool    `json:"available"`
	Count     *int    `json:"count"`
	SHA256    *string `json:"sha256"`
}

type PBPForensicsUnits struct {
	Soak      PBPForensicsUnitState `json:"dynamicflow-lab-pbp-soak.service"`
	VPNHelper PBPForensicsUnitState `json:"dynamicflow-lab-pbp-vpn-trigger.service"`
	VNC       PBPForensicsUnitState `json:"tigervncserver@:1.service"`
	Mullvad   PBPForensicsUnitState `json:"mullvad-daemon.service"`
}

type PBPForensicsUnitState struct {
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	Result      string `json:"result"`
}

func ValidatePBPForensics(data []byte) (PBPForensicsEvidence, error) {
	var zero PBPForensicsEvidence
	if len(data) == 0 || len(data) > MaximumForensicsBytes {
		return zero, errors.New("PBP forensics is empty or exceeds the 1 MiB bound")
	}
	if data[len(data)-1] != '\n' {
		return zero, errors.New("PBP forensics is not newline-terminated canonical JSON")
	}
	var generic interface{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		return zero, errors.New("PBP forensics is not valid JSON")
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return zero, errors.New("PBP forensics has trailing content")
	}
	canonical, err := json.Marshal(generic)
	if err != nil {
		return zero, errors.New("PBP forensics cannot be canonicalized")
	}
	canonical = append(canonical, '\n')
	if err := validatePBPForensicsShape(generic); err != nil {
		return zero, err
	}
	if !bytes.Equal(data, canonical) {
		return zero, errors.New("PBP forensics is not strict canonical JSON")
	}
	strict := json.NewDecoder(bytes.NewReader(data))
	strict.DisallowUnknownFields()
	var evidence PBPForensicsEvidence
	if err := strict.Decode(&evidence); err != nil {
		return zero, errors.New("PBP forensics does not match the strict schema")
	}
	if err := strict.Decode(&trailing); !errors.Is(err, io.EOF) {
		return zero, errors.New("PBP forensics strict schema has trailing content")
	}
	if evidence.Schema != 1 || evidence.Test != "pbp-forensics" || evidence.Status != "captured" {
		return zero, errors.New("PBP forensics is not a captured result for the fixed test")
	}
	if !forensicUTCRE.MatchString(evidence.StartedAt) || !forensicUTCRE.MatchString(evidence.CollectedAt) {
		return zero, errors.New("PBP forensics timestamps are not fixed UTC-second values")
	}
	started, startErr := time.Parse(time.RFC3339, evidence.StartedAt)
	collected, collectedErr := time.Parse(time.RFC3339, evidence.CollectedAt)
	if startErr != nil || collectedErr != nil || collected.Before(started) {
		return zero, errors.New("PBP forensics does not bind evidence to the secure soak start")
	}
	if err := validatePBPForensicsEvidence(evidence); err != nil {
		return zero, err
	}
	return evidence, nil
}

func validatePBPForensicsShape(value interface{}) error {
	root, err := exactForensicsObject(value, "root", "schema", "test", "status", "started_at", "collected_at", "desktop", "profile", "persona", "runtime_logs", "apparmor_denied", "kernel_oom", "kernel_segfault", "kernel_killed", "coredumps", "systemd_units")
	if err != nil {
		return err
	}
	if _, err = exactForensicsObject(root["desktop"], "desktop", "xfce_active", "display_bound", "xauthority_bound", "vnc_unit_active", "vnc_loopback_5901", "vnc_public_5901"); err != nil {
		return err
	}
	if _, err = exactForensicsObject(root["profile"], "profile", "profile_process_count", "app_lock_present", "app_lock_free", "native_lock_count"); err != nil {
		return err
	}
	persona, err := exactForensicsObject(root["persona"], "persona", "baseline", "current", "unchanged")
	if err != nil {
		return err
	}
	for _, name := range []string{"baseline", "current"} {
		if _, err = exactForensicsObject(persona[name], "persona."+name, "sha256", "inode", "size"); err != nil {
			return err
		}
	}
	logs, err := exactForensicsObject(root["runtime_logs"], "runtime_logs", "count", "sha256", "events")
	if err != nil {
		return err
	}
	if _, err = exactForensicsObject(logs["events"], "runtime_logs.events", "runtime_stderr", "runtime_stderr_capture_error", "runtime_stderr_capture_incomplete", "launch_end", "launch_lifecycle_complete", "browser_context_started", "browser_context_closed", "browser_page_opened", "browser_page_closed", "browser_page_crashed", "playwright_dispatch_failed"); err != nil {
		return err
	}
	for _, name := range []string{"apparmor_denied", "kernel_oom", "kernel_segfault", "kernel_killed", "coredumps"} {
		if _, err = exactForensicsObject(root[name], name, "available", "count", "sha256"); err != nil {
			return err
		}
	}
	units, err := exactForensicsObject(root["systemd_units"], "systemd_units", "dynamicflow-lab-pbp-soak.service", "dynamicflow-lab-pbp-vpn-trigger.service", "tigervncserver@:1.service", "mullvad-daemon.service")
	if err != nil {
		return err
	}
	for name, unit := range units {
		if _, err = exactForensicsObject(unit, "systemd_units."+name, "load_state", "active_state", "sub_state", "result"); err != nil {
			return err
		}
	}
	return nil
}

func exactForensicsObject(value interface{}, path string, keys ...string) (map[string]interface{}, error) {
	object, ok := value.(map[string]interface{})
	if !ok || len(object) != len(keys) {
		return nil, fmt.Errorf("PBP forensics %s does not contain the exact required fields", path)
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return nil, fmt.Errorf("PBP forensics %s is missing field %s", path, key)
		}
	}
	return object, nil
}

func validatePBPForensicsEvidence(evidence PBPForensicsEvidence) error {
	desktop := evidence.Desktop
	if !desktop.XFCEActive || !desktop.DisplayBound || !desktop.XAuthorityBound || !desktop.VNCUnitActive || !desktop.VNCLoopback5901 || desktop.VNCPublic5901 {
		return errors.New("PBP forensics does not prove the bound XFCE/VNC loopback session")
	}
	profile := evidence.Profile
	if profile.ProfileProcessCount != 0 || !profile.AppLockPresent || !profile.AppLockFree || profile.NativeLockCount != 0 {
		return errors.New("PBP forensics does not prove the exact profile and locks are free")
	}
	if !validForensicsMetadata(evidence.Persona.Baseline) || !validForensicsMetadata(evidence.Persona.Current) ||
		!evidence.Persona.Unchanged || evidence.Persona.Baseline != evidence.Persona.Current {
		return errors.New("PBP forensics does not prove stable persona file metadata")
	}
	logs := evidence.RuntimeLogs
	if logs.Count < 1 || logs.Count > 8 || len(logs.SHA256) != logs.Count || !sort.StringsAreSorted(logs.SHA256) {
		return errors.New("PBP forensics runtime-log count or digest set is invalid")
	}
	for _, digest := range logs.SHA256 {
		if !forensicSHA256RE.MatchString(digest) {
			return errors.New("PBP forensics contains an invalid runtime-log digest")
		}
	}
	eventCounts := []int{
		logs.Events.RuntimeStderr, logs.Events.RuntimeStderrCaptureError, logs.Events.RuntimeStderrCaptureIncomplete,
		logs.Events.LaunchEnd, logs.Events.LaunchLifecycleComplete, logs.Events.BrowserContextStarted,
		logs.Events.BrowserContextClosed, logs.Events.BrowserPageOpened, logs.Events.BrowserPageClosed,
		logs.Events.BrowserPageCrashed, logs.Events.PlaywrightDispatchFailed,
	}
	for _, count := range eventCounts {
		if count < 0 || count > 1<<20 {
			return errors.New("PBP forensics contains an invalid runtime event count")
		}
	}
	if logs.Events.LaunchEnd == 0 || logs.Events.LaunchLifecycleComplete == 0 ||
		logs.Events.BrowserContextStarted == 0 || logs.Events.BrowserContextClosed == 0 ||
		logs.Events.BrowserPageOpened == 0 || logs.Events.BrowserPageClosed == 0 {
		return errors.New("PBP forensics is missing browser/Playwright lifecycle evidence")
	}
	findings := []struct {
		name    string
		finding PBPForensicsFinding
	}{
		{"apparmor_denied", evidence.AppArmorDenied},
		{"kernel_oom", evidence.KernelOOM},
		{"kernel_segfault", evidence.KernelSegfault},
		{"kernel_killed", evidence.KernelKilled},
		{"coredumps", evidence.Coredumps},
	}
	for _, item := range findings {
		if err := validatePBPForensicsFinding(item.name, item.finding); err != nil {
			return err
		}
	}
	if evidence.AppArmorDenied.Available != evidence.KernelOOM.Available ||
		evidence.AppArmorDenied.Available != evidence.KernelSegfault.Available ||
		evidence.AppArmorDenied.Available != evidence.KernelKilled.Available {
		return errors.New("PBP forensics kernel-journal availability is inconsistent")
	}
	if err := validatePBPForensicsTransientUnit("soak", evidence.SystemdUnits.Soak); err != nil {
		return err
	}
	if err := validatePBPForensicsTransientUnit("VPN helper", evidence.SystemdUnits.VPNHelper); err != nil {
		return err
	}
	if err := validatePBPForensicsActiveUnit("VNC", evidence.SystemdUnits.VNC); err != nil {
		return err
	}
	if err := validatePBPForensicsActiveUnit("Mullvad", evidence.SystemdUnits.Mullvad); err != nil {
		return err
	}
	return nil
}

func validForensicsMetadata(metadata PBPForensicsFileMetadata) bool {
	return forensicSHA256RE.MatchString(metadata.SHA256) && metadata.Inode > 0 && metadata.Size > 0 && metadata.Size <= 2<<20
}

func validatePBPForensicsFinding(name string, finding PBPForensicsFinding) error {
	if !finding.Available {
		if finding.Count != nil || finding.SHA256 != nil {
			return fmt.Errorf("PBP forensics %s fabricates a finding while unavailable", name)
		}
		return nil
	}
	if finding.Count == nil || finding.SHA256 == nil || *finding.Count < 0 || *finding.Count > 1<<20 || !forensicSHA256RE.MatchString(*finding.SHA256) {
		return fmt.Errorf("PBP forensics %s is missing a bounded count or digest", name)
	}
	return nil
}

func validatePBPForensicsTransientUnit(name string, unit PBPForensicsUnitState) error {
	if unit.LoadState != "loaded" || (unit.ActiveState != "inactive" && unit.ActiveState != "failed") ||
		(unit.SubState != "dead" && unit.SubState != "failed") || !forensicStateRE.MatchString(unit.Result) {
		return fmt.Errorf("PBP forensics %s unit has no bounded final state", name)
	}
	return nil
}

func validatePBPForensicsActiveUnit(name string, unit PBPForensicsUnitState) error {
	if unit.LoadState != "loaded" || unit.ActiveState != "active" || unit.SubState != "running" ||
		(unit.Result != "success" && unit.Result != "none") {
		return fmt.Errorf("PBP forensics %s unit is not active and healthy", name)
	}
	return nil
}
