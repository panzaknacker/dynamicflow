package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/servingruntime"
	"dynamicflow/internal/tlsutil"
)

func TestServingReferenceV2PreservesCustomReleaseAndPublicKeySourcesAsDefaults(t *testing.T) {
	operatorRoot := privateTempDir(t)
	store, err := localstate.Open(operatorRoot)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &commandContext{store: store}
	existing := validServingReferenceFixture(t)

	var stateRoot, listen, publicURL, releaseRoot, desiredKey, controlKey, serviceUser string
	explicitReleaseKey := "/operator/explicit/release.public.pem"
	releaseKey := explicitReleaseKey
	if err := applyLocalServingReferenceDefaults(
		ctx, existing, &stateRoot, &listen, &publicURL, &releaseRoot, &releaseKey, &desiredKey, &controlKey, &serviceUser,
	); err != nil {
		t.Fatal(err)
	}
	if stateRoot != existing.StateRoot || listen != existing.Listen || publicURL != existing.PublicURL ||
		releaseRoot != existing.ReleaseRoot || releaseKey != explicitReleaseKey ||
		desiredKey != existing.DesiredPublicKeySource || controlKey != existing.ControlPublicKeySource ||
		serviceUser != existing.ServiceUser {
		t.Fatalf("custom serving defaults were lost: root=%q listen=%q url=%q releases=%q keys=%q/%q/%q user=%q",
			stateRoot, listen, publicURL, releaseRoot, releaseKey, desiredKey, controlKey, serviceUser)
	}

	stateRoot, listen, publicURL, releaseRoot, releaseKey, desiredKey, controlKey, serviceUser = "", "", "", "", "", "", "", ""
	if err := applyLocalServingReferenceDefaults(
		ctx, localServingReference{}, &stateRoot, &listen, &publicURL, &releaseRoot, &releaseKey, &desiredKey, &controlKey, &serviceUser,
	); err != nil {
		t.Fatal(err)
	}
	if stateRoot != "/var/lib/dynamicflow-serving" || listen != "0.0.0.0:8443" || publicURL != "" ||
		releaseRoot != "/var/lib/dynamicflow-serving/releases" || serviceUser != defaultServingServiceUser {
		t.Fatalf("unexpected first-run defaults: %q %q %q %q user=%q", stateRoot, listen, publicURL, releaseRoot, serviceUser)
	}
	for name, path := range map[string]string{"release": releaseKey, "desired-state": desiredKey, "control": controlKey} {
		want, err := store.Path(filepath.Join("keys", "signing", name+".public.pem"))
		if err != nil || path != want {
			t.Fatalf("default %s source=%q want=%q err=%v", name, path, want, err)
		}
	}
}

func TestServingReferenceV2RoundTripAndStrictValidation(t *testing.T) {
	store, err := localstate.Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &commandContext{store: store}
	reference := validServingReferenceFixture(t)
	if err := store.WriteJSON("serving/local.json", reference); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadLocalServingReference(ctx)
	if err != nil || !reflect.DeepEqual(loaded, reference) {
		t.Fatalf("loaded=%#v err=%v, want %#v", loaded, err, reference)
	}

	invalid := []localServingReference{
		func() localServingReference { value := reference; value.Schema = 99; return value }(),
		func() localServingReference { value := reference; value.ServiceUser = ""; return value }(),
		func() localServingReference { value := reference; value.ServiceUser = "custom-serving"; return value }(),
		func() localServingReference { value := reference; value.ServiceUser = "Bad User"; return value }(),
		func() localServingReference {
			value := reference
			value.ReleaseRoot = "/outside/releases"
			return value
		}(),
		func() localServingReference {
			value := reference
			value.ReleaseRoot = value.StateRoot
			return value
		}(),
		func() localServingReference {
			value := reference
			value.ReleaseRoot = filepath.Join(value.StateRoot, "private", "releases")
			return value
		}(),
		func() localServingReference {
			value := reference
			value.ReleaseRoot = filepath.Join(value.StateRoot, "trust", "releases")
			return value
		}(),
		func() localServingReference {
			value := reference
			value.ReleaseRoot = filepath.Join(value.StateRoot, "tls", "releases")
			return value
		}(),
		func() localServingReference {
			value := reference
			value.ReleasePublicKeySource = "relative.pem"
			return value
		}(),
		func() localServingReference { value := reference; value.Fingerprint += "="; return value }(),
		func() localServingReference { value := reference; value.ConfigPath += ".other"; return value }(),
	}
	for index, candidate := range invalid {
		if err := store.WriteJSON("serving/local.json", candidate); err != nil {
			t.Fatal(err)
		}
		if _, err := loadLocalServingReference(ctx); err == nil {
			t.Fatalf("invalid v2 reference %d accepted: %#v", index, candidate)
		}
	}
}

func TestServingReferenceV1MigratesFromMatchingRootCreatedConfigWithoutMutation(t *testing.T) {
	operatorStore, err := localstate.Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &commandContext{store: operatorStore}
	stateRoot := filepath.Join(privateTempDir(t), "serving")
	if err := os.MkdirAll(filepath.Join(stateRoot, "tls"), 0o700); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(stateRoot, "tls", "serving.crt")
	keyPath := filepath.Join(stateRoot, "tls", "serving.key")
	fingerprint, err := tlsutil.GenerateSelfSigned(certPath, keyPath, []string{"serving.example.test"}, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	path := func(name string) string { return filepath.Join(stateRoot, name) }
	config := servingruntime.Config{
		Schema: servingruntime.ConfigSchema, Listen: "127.0.0.1:8443", PublicURL: "https://serving.example.test:8443",
		TLSCert: certPath, TLSKey: keyPath, ReleaseRoot: path("custom-releases"),
		ReleasePublicKey: path("trust/custom-release.public.pem"),
		DesiredPublicKey: path("trust/custom-desired.public.pem"),
		ControlPublicKey: path("trust/custom-control.public.pem"),
		EnrollmentState:  path("private/enrollments.json"), DesiredStateDir: path("private/desired"),
		StatusDir: path("private/status"), LogDir: path("private/logs"), AuditLog: path("private/audit.jsonl"),
		BootstrapScript: path("bootstrap.sh"), MaxClockSkewSeconds: 300,
	}
	configData, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateRoot, "config.json")
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := localServingReference{
		Schema: 1, ConfigPath: configPath, StateRoot: stateRoot,
		PublicURL: config.PublicURL, Listen: config.Listen, Fingerprint: fingerprint,
	}
	if err := operatorStore.WriteJSON("serving/local.json", legacy); err != nil {
		t.Fatal(err)
	}
	migrated, err := loadLocalServingReference(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Schema != localServingReferenceSchema || migrated.ReleaseRoot != config.ReleaseRoot ||
		migrated.ReleasePublicKeySource != config.ReleasePublicKey || migrated.DesiredPublicKeySource != config.DesiredPublicKey ||
		migrated.ControlPublicKeySource != config.ControlPublicKey || migrated.ServiceUser != defaultServingServiceUser {
		t.Fatalf("legacy reference was not migrated from config: %#v", migrated)
	}
	// loading status/config remains read-only. the next successful explicit
	// `flow start serving` persists schema v2 atomically.
	raw, err := operatorStore.ReadFile("serving/local.json")
	if err != nil || !strings.Contains(string(raw), `"schema":1`) || strings.Contains(string(raw), "key_source") {
		t.Fatalf("read-only migration mutated operator state: %s err=%v", raw, err)
	}

	legacy.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	if err := operatorStore.WriteJSON("serving/local.json", legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLocalServingReference(ctx); err == nil {
		t.Fatal("legacy reference with mismatched TLS identity was migrated")
	}
}

func TestMissingServingReferenceRemainsFirstRunNotInvalidState(t *testing.T) {
	store, err := localstate.Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = loadLocalServingReference(&commandContext{store: store})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing reference error=%v, want os.ErrNotExist", err)
	}
}

func validServingReferenceFixture(t *testing.T) localServingReference {
	t.Helper()
	root := filepath.Join(privateTempDir(t), "serving")
	return localServingReference{
		Schema: localServingReferenceSchema, ConfigPath: filepath.Join(root, "config.json"), StateRoot: root,
		ReleaseRoot:            filepath.Join(root, "custom-releases"),
		ReleasePublicKeySource: "/operator/trust/custom-release.public.pem",
		DesiredPublicKeySource: "/operator/trust/custom-desired.public.pem",
		ControlPublicKeySource: "/operator/trust/custom-control.public.pem",
		ServiceUser:            defaultServingServiceUser,
		PublicURL:              "https://serving.example.test:9443", Listen: "127.0.0.1:9443",
		Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
	}
}
