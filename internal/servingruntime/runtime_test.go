package servingruntime

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestValidateRequiresDistinctAbsoluteLogDirectory(t *testing.T) {
	config := validTestConfig(t)
	if err := Validate(config); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"missing":  func(candidate *Config) { candidate.LogDir = "" },
		"relative": func(candidate *Config) { candidate.LogDir = "logs" },
		"root":     func(candidate *Config) { candidate.LogDir = string(filepath.Separator) },
		"duplicate status": func(candidate *Config) {
			candidate.LogDir = candidate.StatusDir
		},
		"duplicate desired": func(candidate *Config) {
			candidate.LogDir = candidate.DesiredStateDir
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := config
			mutate(&candidate)
			if err := Validate(candidate); err == nil {
				t.Fatal("unsafe log directory accepted")
			}
		})
	}
}

func TestLoadPreservesLogDirectoryAndRejectsMissingFieldOrSymlink(t *testing.T) {
	config := validTestConfig(t)
	path := filepath.Join(t.TempDir(), "serving.json")
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || !reflect.DeepEqual(loaded, config) || loaded.LogDir != config.LogDir {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}

	missing := config
	missing.LogDir = ""
	missingData, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, missingData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("config without log_dir accepted")
	}

	link := filepath.Join(t.TempDir(), "serving-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlinked runtime config=%v", err)
	}
}

func validTestConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	path := func(name string) string { return filepath.Join(root, name) }
	return Config{
		Schema: ConfigSchema, Listen: "127.0.0.1:8443", PublicURL: "https://serving.example:8443",
		TLSCert: path("tls.crt"), TLSKey: path("tls.key"), ReleaseRoot: path("releases"),
		ReleasePublicKey: path("release.public.pem"), DesiredPublicKey: path("desired.public.pem"),
		ControlPublicKey: path("control.public.pem"), EnrollmentState: path("enrollments.json"),
		DesiredStateDir: path("desired"), StatusDir: path("status"), LogDir: path("logs"),
		AuditLog: path("audit.jsonl"), BootstrapScript: path("bootstrap.sh"), MaxClockSkewSeconds: 300,
	}
}
