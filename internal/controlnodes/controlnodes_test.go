package controlnodes

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/sshkeys"
)

const (
	testSystemID      = "sys-0123456789abcdef0123456789abcdef"
	testOtherSystemID = "sys-fedcba9876543210fedcba9876543210"
)

var testTime = time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)

type testFixture struct {
	root     *localstate.Store
	keyState *localstate.Store
	keys     *sshkeys.Manager
	manager  *Manager
	key      sshkeys.Record
	input    BindInput
	now      time.Time
}

func TestBindIsIdempotentCanonicalPrivateAndAccessPathsAreNotJSON(t *testing.T) {
	fixture := newFixture(t)
	input := fixture.input
	input.Host = "Control.Example.TEST"
	input.HostPublicKey = "  " + input.HostPublicKey + "   "

	created, wasCreated, err := fixture.manager.Bind(input)
	if err != nil {
		t.Fatal(err)
	}
	if !wasCreated || created.Host != "control.example.test" || created.Port != 22 ||
		created.Lifecycle != LifecycleBound || created.Revision != 1 || created.SchemaVersion != SchemaVersion ||
		created.HostPublicKey != strings.TrimSpace(fixture.input.HostPublicKey) || created.HostFingerprint == "" ||
		!created.CreatedAt.Equal(testTime) || !created.UpdatedAt.Equal(testTime) {
		t.Fatalf("created control = %+v, created=%v", created, wasCreated)
	}

	again, wasCreated, err := fixture.manager.Bind(input)
	if err != nil || wasCreated || !reflect.DeepEqual(again, created) {
		t.Fatalf("idempotent bind = %+v, created=%v, err=%v", again, wasCreated, err)
	}
	got, err := fixture.manager.Get(testSystemID, "control-1")
	if err != nil || !reflect.DeepEqual(got, created) {
		t.Fatalf("get = %+v, err=%v", got, err)
	}

	knownHostsPath, err := fixture.root.Path(knownHostsRelative(testSystemID, "control-1"))
	if err != nil {
		t.Fatal(err)
	}
	knownHosts, err := os.ReadFile(knownHostsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(knownHosts) != "control.example.test "+created.HostPublicKey+"\n" {
		t.Fatalf("known_hosts = %q", knownHosts)
	}
	assertMode(t, knownHostsPath, localstate.FileMode, false)
	metadataPath, err := fixture.root.Path(metadataRelative(testSystemID, "control-1"))
	if err != nil {
		t.Fatal(err)
	}
	assertMode(t, metadataPath, localstate.FileMode, false)
	assertMode(t, filepath.Dir(metadataPath), localstate.DirMode, true)

	material, err := fixture.manager.AccessMaterial(testSystemID, "control-1")
	if err != nil {
		t.Fatal(err)
	}
	if material.IdentityPath == "" || material.KnownHostsPath != knownHostsPath ||
		material.Host != created.Host || material.HostFingerprint != created.HostFingerprint {
		t.Fatalf("access material = %+v", material)
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{material.IdentityPath, material.KnownHostsPath, "IdentityPath", "KnownHostsPath", "identity_path", "known_hosts_path"} {
		if forbidden != "" && bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("access JSON leaks %q: %s", forbidden, encoded)
		}
	}

	listed, err := fixture.manager.List(testSystemID)
	if err != nil || len(listed) != 1 || !reflect.DeepEqual(listed[0], created) {
		t.Fatalf("list = %+v, err=%v", listed, err)
	}
}

func TestReadOperationsDoNotCreateControlState(t *testing.T) {
	fixture := newFixture(t)
	directory, err := fixture.root.Path(controlsRelative(testSystemID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("manager construction created control state: %v", err)
	}
	if _, err := fixture.manager.Get(testSystemID, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing get error = %v", err)
	}
	listed, err := fixture.manager.List(testSystemID)
	if err != nil || len(listed) != 0 {
		t.Fatalf("empty list = %+v, err=%v", listed, err)
	}
	if _, err := fixture.manager.AccessMaterial(testSystemID, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing access error = %v", err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read operation created control state: %v", err)
	}
}

func TestBindSupportsOnlyCanonicalAllowedOperatingSystemsAndEvidence(t *testing.T) {
	fixture := newFixture(t)
	input := fixture.input
	input.Host = "2001:0DB8:0:0:0:0:0:7"
	input.Port = 2222
	input.SSHUser = "ubuntu"
	input.OperatingSystem = OSUbuntu2404
	input.EvidenceSource = EvidenceProviderAttestation
	record, _, err := fixture.manager.Bind(input)
	if err != nil {
		t.Fatal(err)
	}
	if record.Host != "2001:db8::7" || record.Port != 2222 || record.OperatingSystem != OSUbuntu2404 ||
		record.EvidenceSource != EvidenceProviderAttestation {
		t.Fatalf("normalized record = %+v", record)
	}
	data, err := fixture.root.ReadFile(knownHostsRelative(testSystemID, input.Name))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "[2001:db8::7]:2222 "+record.HostPublicKey+"\n" {
		t.Fatalf("IPv6 known_hosts = %q", data)
	}
}

func TestConflictingRebindsFailClosedWithoutChangingTrust(t *testing.T) {
	fixture := newFixture(t)
	original, _, err := fixture.manager.Bind(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	secondKey := seedBootstrapKey(t, fixture.keyState, "control-alternate", 1, 19, "")
	secondRef := keyRef(secondKey)
	otherHostKey := testEd25519PublicKey(77, "other-host")

	tests := map[string]func(*BindInput){
		"host":          func(input *BindInput) { input.Host = "203.0.113.99" },
		"port":          func(input *BindInput) { input.Port = 2222 },
		"user":          func(input *BindInput) { input.SSHUser = "ubuntu" },
		"os":            func(input *BindInput) { input.OperatingSystem = OSUbuntu2404 },
		"bootstrap-key": func(input *BindInput) { input.BootstrapKey = secondRef },
		"host-key":      func(input *BindInput) { input.HostPublicKey = otherHostKey },
		"evidence":      func(input *BindInput) { input.EvidenceSource = EvidenceProviderAttestation },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := fixture.input
			mutate(&changed)
			if _, created, err := fixture.manager.Bind(changed); !errors.Is(err, ErrBindingConflict) || created {
				t.Fatalf("conflicting bind created=%v, err=%v", created, err)
			}
			current, err := fixture.manager.Get(testSystemID, fixture.input.Name)
			if err != nil || !reflect.DeepEqual(current, original) {
				t.Fatalf("binding changed after conflict: %+v, err=%v", current, err)
			}
		})
	}
}

func TestBindRejectsUnsafeInputsAndWrongBootstrapIdentity(t *testing.T) {
	if _, err := NewManager(nil, nil); !errors.Is(err, ErrInvalidManager) {
		t.Fatalf("nil manager error = %v", err)
	}
	fixture := newFixture(t)
	otherFingerprint := fingerprintFor(t, testEd25519PublicKey(33, "different"))
	tests := map[string]func(*BindInput){
		"system-path":       func(input *BindInput) { input.SystemID = "../system" },
		"node-path":         func(input *BindInput) { input.Name = "../control" },
		"root-user":         func(input *BindInput) { input.SSHUser = "root" },
		"option-host":       func(input *BindInput) { input.Host = "-oProxyCommand=evil" },
		"invalid-port":      func(input *BindInput) { input.Port = 65536 },
		"unsupported-os":    func(input *BindInput) { input.OperatingSystem = "debian-12" },
		"network-evidence":  func(input *BindInput) { input.EvidenceSource = "ssh-keyscan" },
		"non-bootstrap-key": func(input *BindInput) { input.BootstrapKey.Scope = sshkeys.Instance },
		"wrong-generation":  func(input *BindInput) { input.BootstrapKey.Generation++ },
		"wrong-fingerprint": func(input *BindInput) { input.BootstrapKey.Fingerprint = otherFingerprint },
		"non-ed25519-host":  func(input *BindInput) { input.HostPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := fixture.input
			mutate(&input)
			if _, created, err := fixture.manager.Bind(input); err == nil || created {
				t.Fatalf("unsafe input was accepted: created=%v", created)
			}
		})
	}

	rootKey := seedBootstrapKey(t, fixture.root, "root-scoped", 1, 42, "")
	wrongManager, err := NewManager(fixture.root, sshkeys.NewManager(fixture.root), WithClock(func() time.Time { return testTime }))
	if err != nil {
		t.Fatal(err)
	}
	wrongSystemInput := fixture.input
	wrongSystemInput.Name = "control-root-key"
	wrongSystemInput.BootstrapKey = keyRef(rootKey)
	if _, _, err := wrongManager.Bind(wrongSystemInput); !errors.Is(err, ErrBootstrapKeyMismatch) {
		t.Fatalf("root-scoped bootstrap identity error = %v", err)
	}
}

func TestLifecycleCASIsStrictlyForwardAndRevocationIsTerminal(t *testing.T) {
	fixture := newFixture(t)
	record, _, err := fixture.manager.Bind(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.manager.Transition(testSystemID, record.Name, record.Revision, LifecycleReady); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("skipped transition error = %v", err)
	}

	for _, next := range []Lifecycle{LifecycleConnectivityVerified, LifecycleInstalling} {
		fixture.now = fixture.now.Add(time.Minute)
		previous := record
		record, err = fixture.manager.Transition(testSystemID, record.Name, record.Revision, next)
		if err != nil {
			t.Fatal(err)
		}
		if record.Lifecycle != next || record.Revision != previous.Revision+1 ||
			!record.UpdatedAt.Equal(fixture.now) || !record.CreatedAt.Equal(previous.CreatedAt) {
			t.Fatalf("transition to %s = %+v", next, record)
		}
		if _, err := fixture.manager.Transition(testSystemID, record.Name, previous.Revision, next); !errors.Is(err, ErrRevisionConflict) {
			t.Fatalf("stale CAS error = %v", err)
		}
	}
	if _, err := fixture.manager.Transition(testSystemID, record.Name, record.Revision, LifecycleReady); !errors.Is(err, ErrBootstrapRevocation) {
		t.Fatalf("ready before bootstrap revocation error = %v", err)
	}
	management := seedSSHKey(t, fixture.keyState, sshkeys.Control, "control-management", 1, 31, "")
	fixture.now = fixture.now.Add(time.Minute)
	record, staged, err := fixture.manager.Stage(testSystemID, record.Name, record.Revision, keyRef(management), ManagementAccessUser)
	if err != nil || !staged {
		t.Fatalf("stage management access = %+v, staged=%v, err=%v", record, staged, err)
	}
	if _, err := fixture.keys.Revoke(sshkeys.Bootstrap, fixture.key.Name); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Minute)
	record, activated, err := fixture.manager.Activate(testSystemID, record.Name, record.Revision, ActivationConfirmation{
		ControlKey: keyRef(management), AccessUser: ManagementAccessUser,
		ManagementProofVerified: true, BootstrapRevocationVerified: true,
	})
	if err != nil || !activated {
		t.Fatalf("activate management access = %+v, activated=%v, err=%v", record, activated, err)
	}
	fixture.now = fixture.now.Add(time.Minute)
	previous := record
	record, err = fixture.manager.Transition(testSystemID, record.Name, record.Revision, LifecycleReady)
	if err != nil || record.Lifecycle != LifecycleReady || record.Revision != previous.Revision+1 {
		t.Fatalf("ready after management activation = %+v, err=%v", record, err)
	}
	if _, err := fixture.manager.Transition(testSystemID, record.Name, record.Revision, LifecycleReady); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("same-state transition error = %v", err)
	}

	fixture.now = fixture.now.Add(time.Minute)
	record, err = fixture.manager.Transition(testSystemID, record.Name, record.Revision, LifecycleRevoked)
	if err != nil || record.Lifecycle != LifecycleRevoked || record.RevokedAt == nil || !record.RevokedAt.Equal(fixture.now) {
		t.Fatalf("revoke = %+v, err=%v", record, err)
	}
	if _, err := fixture.manager.AccessMaterial(testSystemID, record.Name); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked access error = %v", err)
	}
	if _, err := fixture.manager.Transition(testSystemID, record.Name, record.Revision, LifecycleRevoked); !errors.Is(err, ErrRevoked) {
		t.Fatalf("repeated revoke error = %v", err)
	}
	if _, _, err := fixture.manager.Bind(fixture.input); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked rebind error = %v", err)
	}
}

func TestBackwardClockAndBootstrapRotationCannotAdvanceLifecycle(t *testing.T) {
	fixture := newFixture(t)
	record, _, err := fixture.manager.Bind(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	fixture.now = record.UpdatedAt.Add(-time.Second)
	if _, err := fixture.manager.Transition(testSystemID, record.Name, record.Revision, LifecycleConnectivityVerified); !errors.Is(err, ErrInvalidControlNode) {
		t.Fatalf("backward clock error = %v", err)
	}
	current, err := fixture.manager.Get(testSystemID, record.Name)
	if err != nil || !reflect.DeepEqual(current, record) {
		t.Fatalf("backward clock changed record: %+v, err=%v", current, err)
	}

	rotated := seedBootstrapKey(t, fixture.keyState, fixture.key.Name, 2, 88, fixture.key.Fingerprint)
	if rotated.Generation != 2 {
		t.Fatal("fixture did not rotate")
	}
	fixture.now = testTime.Add(time.Minute)
	if _, err := fixture.manager.AccessMaterial(testSystemID, record.Name); !errors.Is(err, ErrBootstrapKeyMismatch) {
		t.Fatalf("rotated access error = %v", err)
	}
	if _, err := fixture.manager.Transition(testSystemID, record.Name, record.Revision, LifecycleConnectivityVerified); !errors.Is(err, ErrBootstrapKeyMismatch) {
		t.Fatalf("rotated transition error = %v", err)
	}
	if rebound, created, err := fixture.manager.Bind(fixture.input); err != nil || created || !reflect.DeepEqual(rebound, record) {
		t.Fatalf("exact rebind after local key rotation = %+v, created=%v, err=%v", rebound, created, err)
	}
	if _, err := fixture.manager.Transition(testSystemID, record.Name, record.Revision, LifecycleRevoked); err != nil {
		t.Fatalf("explicit revocation must remain available after key loss: %v", err)
	}
}

func TestStageKeepsExactBootstrapAccessAndBindsPendingManagementUser(t *testing.T) {
	fixture := newFixture(t)
	bound, _, err := fixture.manager.Bind(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	if bound.Access.Phase != AccessBootstrap || bound.Access.Active != keyRef(fixture.key) ||
		bound.Access.ActiveAccessUser != bound.SSHUser || !isZeroKeyRef(bound.Access.Pending) ||
		bound.Access.PendingAccessUser != "" {
		t.Fatalf("initial access state = %+v", bound.Access)
	}
	if _, err := fixture.manager.PendingAccessMaterial(bound.SystemID, bound.Name); !errors.Is(err, ErrNoPendingAccess) {
		t.Fatalf("pending access before Stage error = %v", err)
	}
	bootstrapMaterial, err := fixture.manager.AccessMaterial(bound.SystemID, bound.Name)
	if err != nil {
		t.Fatal(err)
	}
	if bootstrapMaterial.SSHUser != bound.SSHUser || bootstrapMaterial.Identity != keyRef(fixture.key) ||
		!strings.Contains(bootstrapMaterial.IdentityPath, filepath.Join("keys", string(sshkeys.Bootstrap))) {
		t.Fatalf("bootstrap access material = %+v", bootstrapMaterial)
	}

	management := seedSSHKey(t, fixture.keyState, sshkeys.Control, "control-management", 1, 41, "")
	managementRef := keyRef(management)
	immutableBootstrap := bound.BootstrapKey
	immutableBootstrapUser := bound.SSHUser
	fixture.now = fixture.now.Add(time.Minute)
	if _, changed, err := fixture.manager.Stage(bound.SystemID, bound.Name, bound.Revision+1, managementRef, ManagementAccessUser); !errors.Is(err, ErrRevisionConflict) || changed {
		t.Fatalf("stale Stage CAS changed=%v, err=%v", changed, err)
	}
	staged, changed, err := fixture.manager.Stage(bound.SystemID, bound.Name, bound.Revision, managementRef, ManagementAccessUser)
	if err != nil || !changed {
		t.Fatalf("Stage = %+v, changed=%v, err=%v", staged, changed, err)
	}
	if staged.Revision != bound.Revision+1 || staged.Access.Phase != AccessStaged ||
		staged.Access.Active != keyRef(fixture.key) || staged.Access.ActiveAccessUser != immutableBootstrapUser ||
		staged.Access.Pending != managementRef || staged.Access.PendingAccessUser != ManagementAccessUser ||
		staged.BootstrapKey != immutableBootstrap || staged.SSHUser != immutableBootstrapUser {
		t.Fatalf("staged access state = %+v", staged)
	}

	active, err := fixture.manager.AccessMaterial(bound.SystemID, bound.Name)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := fixture.manager.PendingAccessMaterial(bound.SystemID, bound.Name)
	if err != nil {
		t.Fatal(err)
	}
	if active.Identity != keyRef(fixture.key) || active.SSHUser != immutableBootstrapUser ||
		active.IdentityPath != bootstrapMaterial.IdentityPath {
		t.Fatalf("Stage changed active bootstrap access = %+v", active)
	}
	if pending.Identity != managementRef || pending.SSHUser != ManagementAccessUser ||
		pending.Host != active.Host || pending.Port != active.Port ||
		pending.HostFingerprint != active.HostFingerprint || pending.KnownHostsPath != active.KnownHostsPath ||
		!strings.Contains(pending.IdentityPath, filepath.Join("keys", string(sshkeys.Control))) {
		t.Fatalf("strict pending management access = %+v", pending)
	}
	assertNoPrivateStateJSON(t, fixture, staged, active, pending)

	replayed, changed, err := fixture.manager.Stage(bound.SystemID, bound.Name, bound.Revision, managementRef, ManagementAccessUser)
	if err != nil || changed || !reflect.DeepEqual(replayed, staged) {
		t.Fatalf("exact stale-revision Stage replay = %+v, changed=%v, err=%v", replayed, changed, err)
	}
	other := seedSSHKey(t, fixture.keyState, sshkeys.Control, "other-management", 1, 43, "")
	if _, changed, err := fixture.manager.Stage(bound.SystemID, bound.Name, bound.Revision, keyRef(other), ManagementAccessUser); !errors.Is(err, ErrPendingAccessConflict) || changed {
		t.Fatalf("different pending-key replay changed=%v, err=%v", changed, err)
	}
	if _, changed, err := fixture.manager.Stage(bound.SystemID, bound.Name, bound.Revision, managementRef, "dynamicflow-ops"); !errors.Is(err, ErrPendingAccessConflict) || changed {
		t.Fatalf("different pending-user replay changed=%v, err=%v", changed, err)
	}
}

func TestStageRejectsRootInjectionAndNonDedicatedManagementUsers(t *testing.T) {
	tests := []string{
		"root", "-oProxyCommand=evil", "dynamicflow control", "dynamicflow-control\nroot", "UPPER", "", "dynamicflow-ops",
	}
	for _, accessUser := range tests {
		t.Run(strings.ReplaceAll(accessUser, "/", "_"), func(t *testing.T) {
			fixture := newFixture(t)
			bound, _, err := fixture.manager.Bind(fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			management := seedSSHKey(t, fixture.keyState, sshkeys.Control, "control-management", 1, 45, "")
			if _, changed, err := fixture.manager.Stage(bound.SystemID, bound.Name, bound.Revision, keyRef(management), accessUser); !errors.Is(err, ErrInvalidControlNode) || changed {
				t.Fatalf("unsafe/non-dedicated user %q changed=%v, err=%v", accessUser, changed, err)
			}
			current, err := fixture.manager.Get(bound.SystemID, bound.Name)
			if err != nil || !reflect.DeepEqual(current, bound) {
				t.Fatalf("rejected Stage changed record: %+v, err=%v", current, err)
			}
		})
	}
	fixture := newFixture(t)
	input := fixture.input
	input.SSHUser = ManagementAccessUser
	if _, created, err := fixture.manager.Bind(input); !errors.Is(err, ErrInvalidControlNode) || created {
		t.Fatalf("dedicated management user accepted as bootstrap: created=%v err=%v", created, err)
	}
}

func TestActivateRequiresProofAndRevocationThenSwitchesKeyAndUserAtomically(t *testing.T) {
	fixture := newFixture(t)
	bound, _, err := fixture.manager.Bind(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	management := seedSSHKey(t, fixture.keyState, sshkeys.Control, "control-management", 1, 51, "")
	managementRef := keyRef(management)
	fixture.now = fixture.now.Add(time.Minute)
	staged, changed, err := fixture.manager.Stage(bound.SystemID, bound.Name, bound.Revision, managementRef, ManagementAccessUser)
	if err != nil || !changed {
		t.Fatalf("Stage changed=%v err=%v", changed, err)
	}
	confirmation := ActivationConfirmation{
		ControlKey: managementRef, AccessUser: ManagementAccessUser,
		ManagementProofVerified: true, BootstrapRevocationVerified: true,
	}

	proofFailures := []ActivationConfirmation{
		{ControlKey: managementRef, AccessUser: ManagementAccessUser, BootstrapRevocationVerified: true},
		{ControlKey: managementRef, AccessUser: ManagementAccessUser, ManagementProofVerified: true},
	}
	for _, incomplete := range proofFailures {
		if _, activated, err := fixture.manager.Activate(bound.SystemID, bound.Name, staged.Revision, incomplete); !errors.Is(err, ErrActivationProof) || activated {
			t.Fatalf("incomplete proof activated=%v, err=%v", activated, err)
		}
	}
	for _, unsafeUser := range []string{"root", "-oProxyCommand=evil", "dynamicflow control", "dynamicflow-control\nroot"} {
		unsafe := confirmation
		unsafe.AccessUser = unsafeUser
		if _, activated, err := fixture.manager.Activate(bound.SystemID, bound.Name, staged.Revision, unsafe); !errors.Is(err, ErrInvalidControlNode) || activated {
			t.Fatalf("unsafe activation user %q activated=%v, err=%v", unsafeUser, activated, err)
		}
	}
	wrongUser := confirmation
	wrongUser.AccessUser = "dynamicflow-ops"
	if _, activated, err := fixture.manager.Activate(bound.SystemID, bound.Name, staged.Revision, wrongUser); !errors.Is(err, ErrPendingAccessConflict) || activated {
		t.Fatalf("different-user Activate replay activated=%v, err=%v", activated, err)
	}
	if _, activated, err := fixture.manager.Activate(bound.SystemID, bound.Name, staged.Revision, confirmation); !errors.Is(err, ErrBootstrapRevocation) || activated {
		t.Fatalf("active bootstrap was accepted: activated=%v, err=%v", activated, err)
	}
	if _, activated, err := fixture.manager.Activate(bound.SystemID, bound.Name, staged.Revision+1, confirmation); !errors.Is(err, ErrRevisionConflict) || activated {
		t.Fatalf("stale Activate CAS activated=%v, err=%v", activated, err)
	}
	current, err := fixture.manager.Get(bound.SystemID, bound.Name)
	if err != nil || !reflect.DeepEqual(current, staged) {
		t.Fatalf("failed activation changed state: %+v, err=%v", current, err)
	}

	if _, err := fixture.keys.Revoke(sshkeys.Bootstrap, fixture.key.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.manager.AccessMaterial(bound.SystemID, bound.Name); !errors.Is(err, ErrBootstrapKeyMismatch) {
		t.Fatalf("revoked Bootstrap silently fell back before Activate: %v", err)
	}
	if pending, err := fixture.manager.PendingAccessMaterial(bound.SystemID, bound.Name); err != nil ||
		pending.Identity != managementRef || pending.SSHUser != ManagementAccessUser {
		t.Fatalf("pending proof material after bootstrap revoke = %+v, err=%v", pending, err)
	}

	fixture.now = fixture.now.Add(time.Minute)
	activatedRecord, activated, err := fixture.manager.Activate(bound.SystemID, bound.Name, staged.Revision, confirmation)
	if err != nil || !activated {
		t.Fatalf("Activate = %+v, activated=%v, err=%v", activatedRecord, activated, err)
	}
	if activatedRecord.Access.Phase != AccessManagement || activatedRecord.Access.Active != managementRef ||
		activatedRecord.Access.ActiveAccessUser != ManagementAccessUser ||
		!isZeroKeyRef(activatedRecord.Access.Pending) || activatedRecord.Access.PendingAccessUser != "" ||
		activatedRecord.BootstrapKey != bound.BootstrapKey || activatedRecord.SSHUser != bound.SSHUser ||
		!activatedRecord.Access.ManagementProofVerifiedAt.Equal(fixture.now) ||
		!activatedRecord.Access.BootstrapRevocationVerifiedAt.Equal(fixture.now) {
		t.Fatalf("activated access state = %+v", activatedRecord)
	}
	active, err := fixture.manager.AccessMaterial(bound.SystemID, bound.Name)
	if err != nil || active.Identity != managementRef || active.SSHUser != ManagementAccessUser ||
		!strings.Contains(active.IdentityPath, filepath.Join("keys", string(sshkeys.Control))) {
		t.Fatalf("strict active management material = %+v, err=%v", active, err)
	}
	if _, err := fixture.manager.PendingAccessMaterial(bound.SystemID, bound.Name); !errors.Is(err, ErrNoPendingAccess) {
		t.Fatalf("pending access remained after Activate: %v", err)
	}
	replayed, activated, err := fixture.manager.Activate(bound.SystemID, bound.Name, staged.Revision, confirmation)
	if err != nil || activated || !reflect.DeepEqual(replayed, activatedRecord) {
		t.Fatalf("exact stale-revision Activate replay = %+v, activated=%v, err=%v", replayed, activated, err)
	}
	if replayedStage, changed, err := fixture.manager.Stage(bound.SystemID, bound.Name, bound.Revision, managementRef, ManagementAccessUser); err != nil || changed || !reflect.DeepEqual(replayedStage, activatedRecord) {
		t.Fatalf("exact Stage replay after Activate = %+v, changed=%v, err=%v", replayedStage, changed, err)
	}
}

func TestManagementKeyAndSystemPathChangesFailClosedWithoutFallback(t *testing.T) {
	t.Run("pending-rotation", func(t *testing.T) {
		fixture := newFixture(t)
		bound, _, err := fixture.manager.Bind(fixture.input)
		if err != nil {
			t.Fatal(err)
		}
		management := seedSSHKey(t, fixture.keyState, sshkeys.Control, "control-management", 1, 61, "")
		staged, _, err := fixture.manager.Stage(bound.SystemID, bound.Name, bound.Revision, keyRef(management), ManagementAccessUser)
		if err != nil {
			t.Fatal(err)
		}
		seedSSHKey(t, fixture.keyState, sshkeys.Control, management.Name, 2, 62, management.Fingerprint)
		if _, err := fixture.manager.PendingAccessMaterial(bound.SystemID, bound.Name); !errors.Is(err, ErrManagementKeyMismatch) {
			t.Fatalf("rotated pending key error = %v", err)
		}
		confirmation := ActivationConfirmation{
			ControlKey: keyRef(management), AccessUser: ManagementAccessUser,
			ManagementProofVerified: true, BootstrapRevocationVerified: true,
		}
		if _, activated, err := fixture.manager.Activate(bound.SystemID, bound.Name, staged.Revision, confirmation); !errors.Is(err, ErrManagementKeyMismatch) || activated {
			t.Fatalf("rotated pending key activated=%v, err=%v", activated, err)
		}
		if material, err := fixture.manager.AccessMaterial(bound.SystemID, bound.Name); err != nil || material.Identity != keyRef(fixture.key) {
			t.Fatalf("pending failure changed active Bootstrap = %+v, err=%v", material, err)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *testFixture, sshkeys.Record)
		want   error
	}{
		{
			name: "active-rotation",
			mutate: func(t *testing.T, fixture *testFixture, management sshkeys.Record) {
				seedSSHKey(t, fixture.keyState, sshkeys.Control, management.Name, 2, 64, management.Fingerprint)
			},
			want: ErrManagementKeyMismatch,
		},
		{
			name: "active-revocation",
			mutate: func(t *testing.T, fixture *testFixture, management sshkeys.Record) {
				if _, err := fixture.keys.Revoke(sshkeys.Control, management.Name); err != nil {
					t.Fatal(err)
				}
			},
			want: ErrManagementKeyMismatch,
		},
		{
			name: "bootstrap-reactivation-or-rotation",
			mutate: func(t *testing.T, fixture *testFixture, _ sshkeys.Record) {
				seedSSHKey(t, fixture.keyState, sshkeys.Bootstrap, fixture.key.Name, 2, 66, fixture.key.Fingerprint)
			},
			want: ErrBootstrapRevocation,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			activated, management := activateFixtureManagement(t, fixture, 63)
			test.mutate(t, fixture, management)
			if _, err := fixture.manager.AccessMaterial(activated.SystemID, activated.Name); !errors.Is(err, test.want) {
				t.Fatalf("changed active access error = %v, want %v", err, test.want)
			}
			if _, err := fixture.manager.Transition(activated.SystemID, activated.Name, activated.Revision, LifecycleConnectivityVerified); !errors.Is(err, test.want) {
				t.Fatalf("lifecycle advanced with changed access: %v", err)
			}
			if _, err := fixture.manager.Transition(activated.SystemID, activated.Name, activated.Revision, LifecycleRevoked); err != nil {
				t.Fatalf("explicit lifecycle revocation unavailable: %v", err)
			}
		})
	}

	t.Run("pending-private-path-symlink", func(t *testing.T) {
		fixture := newFixture(t)
		bound, _, err := fixture.manager.Bind(fixture.input)
		if err != nil {
			t.Fatal(err)
		}
		management := seedSSHKey(t, fixture.keyState, sshkeys.Control, "control-management", 1, 68, "")
		if _, _, err := fixture.manager.Stage(bound.SystemID, bound.Name, bound.Revision, keyRef(management), ManagementAccessUser); err != nil {
			t.Fatal(err)
		}
		privatePath, err := fixture.keyState.Path(filepath.Join(
			"keys", string(sshkeys.Control), management.Name, "generations", generationDirectoryName(1), "id_ed25519",
		))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(privatePath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(t.TempDir(), "outside-private-key"), privatePath); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.manager.PendingAccessMaterial(bound.SystemID, bound.Name); !errors.Is(err, ErrManagementKeyMismatch) {
			t.Fatalf("symlinked pending key error = %v", err)
		}
		if material, err := fixture.manager.AccessMaterial(bound.SystemID, bound.Name); err != nil || material.Identity != keyRef(fixture.key) {
			t.Fatalf("pending path attack changed active Bootstrap = %+v, err=%v", material, err)
		}
	})

	t.Run("identity-store-outside-system", func(t *testing.T) {
		fixture := newFixture(t)
		bound, _, err := fixture.manager.Bind(fixture.input)
		if err != nil {
			t.Fatal(err)
		}
		otherState, err := localstate.Open(filepath.Join(fixture.root.Root(), "systems", testOtherSystemID))
		if err != nil {
			t.Fatal(err)
		}
		seedSSHKey(t, otherState, sshkeys.Bootstrap, fixture.key.Name, 1, 7, "")
		management := seedSSHKey(t, otherState, sshkeys.Control, "control-management", 1, 70, "")
		outsideManager, err := NewManager(
			fixture.root, sshkeys.NewManager(otherState, sshkeys.WithControlScope()),
			WithClock(func() time.Time { return fixture.now }),
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, changed, err := outsideManager.Stage(bound.SystemID, bound.Name, bound.Revision, keyRef(management), ManagementAccessUser); !errors.Is(err, ErrBootstrapKeyMismatch) || changed {
			t.Fatalf("outside-system identity changed=%v, err=%v", changed, err)
		}
		current, err := fixture.manager.Get(bound.SystemID, bound.Name)
		if err != nil || !reflect.DeepEqual(current, bound) {
			t.Fatalf("outside-system attempt changed record: %+v, err=%v", current, err)
		}
	})
}

func TestConcurrentStageAndActivateHaveOneWriterAndIdempotentReplays(t *testing.T) {
	fixture := newFixture(t)
	bound, _, err := fixture.manager.Bind(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	management := seedSSHKey(t, fixture.keyState, sshkeys.Control, "control-management", 1, 73, "")
	managementRef := keyRef(management)
	fixture.now = fixture.now.Add(time.Minute)

	const workers = 32
	var stageWriters atomic.Int32
	var stageReplays atomic.Int32
	var stageErrors atomic.Int32
	var wait sync.WaitGroup
	wait.Add(workers)
	for index := 0; index < workers; index++ {
		go func() {
			defer wait.Done()
			_, changed, err := fixture.manager.Stage(bound.SystemID, bound.Name, bound.Revision, managementRef, ManagementAccessUser)
			switch {
			case err != nil:
				stageErrors.Add(1)
			case changed:
				stageWriters.Add(1)
			default:
				stageReplays.Add(1)
			}
		}()
	}
	wait.Wait()
	if stageWriters.Load() != 1 || stageReplays.Load() != workers-1 || stageErrors.Load() != 0 {
		t.Fatalf("Stage concurrency: writers=%d replays=%d errors=%d", stageWriters.Load(), stageReplays.Load(), stageErrors.Load())
	}
	staged, err := fixture.manager.Get(bound.SystemID, bound.Name)
	if err != nil || staged.Access.Phase != AccessStaged || staged.Revision != bound.Revision+1 {
		t.Fatalf("concurrent Stage result = %+v, err=%v", staged, err)
	}
	if _, err := fixture.keys.Revoke(sshkeys.Bootstrap, fixture.key.Name); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Minute)
	confirmation := ActivationConfirmation{
		ControlKey: managementRef, AccessUser: ManagementAccessUser,
		ManagementProofVerified: true, BootstrapRevocationVerified: true,
	}
	var activateWriters atomic.Int32
	var activateReplays atomic.Int32
	var activateErrors atomic.Int32
	wait = sync.WaitGroup{}
	wait.Add(workers)
	for index := 0; index < workers; index++ {
		go func() {
			defer wait.Done()
			_, changed, err := fixture.manager.Activate(bound.SystemID, bound.Name, staged.Revision, confirmation)
			switch {
			case err != nil:
				activateErrors.Add(1)
			case changed:
				activateWriters.Add(1)
			default:
				activateReplays.Add(1)
			}
		}()
	}
	wait.Wait()
	if activateWriters.Load() != 1 || activateReplays.Load() != workers-1 || activateErrors.Load() != 0 {
		t.Fatalf("Activate concurrency: writers=%d replays=%d errors=%d", activateWriters.Load(), activateReplays.Load(), activateErrors.Load())
	}
	active, err := fixture.manager.AccessMaterial(bound.SystemID, bound.Name)
	if err != nil || active.Identity != managementRef || active.SSHUser != ManagementAccessUser {
		t.Fatalf("concurrent Activate result = %+v, err=%v", active, err)
	}
}

func TestKnownHostsTamperingFailsClosedAndBindDoesNotRepairIt(t *testing.T) {
	fixture := newFixture(t)
	record, _, err := fixture.manager.Bind(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	knownRelative := knownHostsRelative(testSystemID, record.Name)
	if err := fixture.root.WriteFile(knownRelative, []byte("evil.example ssh-ed25519 AAAA\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.manager.Get(testSystemID, record.Name); !errors.Is(err, ErrKnownHostsMismatch) {
		t.Fatalf("tampered get error = %v", err)
	}
	if _, _, err := fixture.manager.Bind(fixture.input); !errors.Is(err, ErrKnownHostsMismatch) {
		t.Fatalf("tampered bind error = %v", err)
	}
	if _, err := fixture.manager.Transition(testSystemID, record.Name, record.Revision, LifecycleConnectivityVerified); !errors.Is(err, ErrKnownHostsMismatch) {
		t.Fatalf("tampered transition error = %v", err)
	}
	if _, err := fixture.manager.AccessMaterial(testSystemID, record.Name); !errors.Is(err, ErrKnownHostsMismatch) {
		t.Fatalf("tampered access error = %v", err)
	}
	stillTampered, err := fixture.root.ReadFile(knownRelative)
	if err != nil || !bytes.HasPrefix(stillTampered, []byte("evil.example")) {
		t.Fatalf("bind silently repaired trust file: %q, err=%v", stillTampered, err)
	}
}

func TestCorruptUnknownAndUnsafeMetadataFailsClosed(t *testing.T) {
	tests := map[string]func(*Record){
		"unknown-schema":    func(record *Record) { record.SchemaVersion = 99 },
		"wrong-system":      func(record *Record) { record.SystemID = testOtherSystemID },
		"wrong-name":        func(record *Record) { record.Name = "control-other" },
		"noncanonical-host": func(record *Record) { record.Host = "CONTROL.EXAMPLE.TEST" },
		"root-user":         func(record *Record) { record.SSHUser = "root" },
		"management-bootstrap-user": func(record *Record) {
			record.SSHUser = ManagementAccessUser
			record.Access.ActiveAccessUser = ManagementAccessUser
		},
		"unsupported-os":       func(record *Record) { record.OperatingSystem = "ubuntu-22.04" },
		"wrong-key-scope":      func(record *Record) { record.BootstrapKey.Scope = sshkeys.Instance },
		"bad-key-fingerprint":  func(record *Record) { record.BootstrapKey.Fingerprint += "=" },
		"host-key-mismatch":    func(record *Record) { record.HostFingerprint = record.BootstrapKey.Fingerprint },
		"network-evidence":     func(record *Record) { record.EvidenceSource = "network" },
		"unknown-lifecycle":    func(record *Record) { record.Lifecycle = "failed" },
		"unknown-access-phase": func(record *Record) { record.Access.Phase = "fallback" },
		"active-user-mismatch": func(record *Record) { record.Access.ActiveAccessUser = "ubuntu" },
		"unexpected-pending-key": func(record *Record) {
			record.Access.Pending = record.BootstrapKey
		},
		"unexpected-pending-user": func(record *Record) {
			record.Access.PendingAccessUser = ManagementAccessUser
		},
		"unexpected-access-proof": func(record *Record) {
			record.Access.ManagementProofVerifiedAt = testTime
		},
		"management-with-bootstrap-key": func(record *Record) {
			record.Access.Phase = AccessManagement
		},
		"ready-before-management": func(record *Record) { record.Lifecycle = LifecycleReady },
		"zero-revision":           func(record *Record) { record.Revision = 0 },
		"unexpected-revocation":   func(record *Record) { revoked := testTime; record.RevokedAt = &revoked },
	}
	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newFixture(t)
			record, _, err := fixture.manager.Bind(fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			corrupt(&record)
			if err := fixture.root.WriteJSON(metadataRelative(testSystemID, fixture.input.Name), record); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.manager.Get(testSystemID, fixture.input.Name); !errors.Is(err, ErrInvalidControlNode) {
				t.Fatalf("corrupt get error = %v", err)
			}
			if _, created, err := fixture.manager.Bind(fixture.input); err == nil || created {
				t.Fatalf("corrupt metadata was overwritten: created=%v, err=%v", created, err)
			}
		})
	}

	t.Run("unknown-json-field", func(t *testing.T) {
		fixture := newFixture(t)
		if _, _, err := fixture.manager.Bind(fixture.input); err != nil {
			t.Fatal(err)
		}
		metadata := metadataRelative(testSystemID, fixture.input.Name)
		data, err := fixture.root.ReadFile(metadata)
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.TrimSpace(data)
		data = append(data[:len(data)-1], []byte(`,"private_key_path":"/tmp/stolen"}`)...)
		data = append(data, '\n')
		data = bytes.ReplaceAll(data, []byte{'\\', '"'}, []byte{'"'})
		if err := fixture.root.WriteFile(metadata, data); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.manager.Get(testSystemID, fixture.input.Name); !errors.Is(err, ErrInvalidControlNode) {
			t.Fatalf("unknown field error = %v", err)
		}
	})
}

func TestConcurrentBindAcrossManagersCreatesExactlyOnce(t *testing.T) {
	fixture := newFixture(t)
	const workers = 48
	start := make(chan struct{})
	results := make(chan Record, workers)
	errorsFound := make(chan error, workers)
	var createdCount atomic.Int32
	var wait sync.WaitGroup
	wait.Add(workers)
	for index := 0; index < workers; index++ {
		go func() {
			defer wait.Done()
			root, err := localstate.Open(fixture.root.Root())
			if err != nil {
				errorsFound <- err
				return
			}
			keyState, err := localstate.Open(fixture.keyState.Root())
			if err != nil {
				errorsFound <- err
				return
			}
			manager, err := NewManager(root, sshkeys.NewManager(keyState), WithClock(func() time.Time { return testTime }))
			if err != nil {
				errorsFound <- err
				return
			}
			<-start
			record, created, err := manager.Bind(fixture.input)
			if err != nil {
				errorsFound <- err
				return
			}
			if created {
				createdCount.Add(1)
			}
			results <- record
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		t.Errorf("concurrent bind: %v", err)
	}
	if createdCount.Load() != 1 {
		t.Fatalf("creator count = %d", createdCount.Load())
	}
	var first *Record
	for record := range results {
		if first == nil {
			copy := record
			first = &copy
		} else if !reflect.DeepEqual(*first, record) {
			t.Fatalf("workers observed different records: %+v != %+v", *first, record)
		}
	}
}

func TestConcurrentCASTransitionHasExactlyOneWinner(t *testing.T) {
	fixture := newFixture(t)
	record, _, err := fixture.manager.Bind(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	var successes atomic.Int32
	var conflicts atomic.Int32
	var unexpected atomic.Int32
	var wait sync.WaitGroup
	wait.Add(workers)
	for index := 0; index < workers; index++ {
		go func() {
			defer wait.Done()
			updated, err := fixture.manager.Transition(testSystemID, record.Name, record.Revision, LifecycleConnectivityVerified)
			switch {
			case err == nil && updated.Revision == 2:
				successes.Add(1)
			case errors.Is(err, ErrRevisionConflict):
				conflicts.Add(1)
			default:
				unexpected.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || conflicts.Load() != workers-1 || unexpected.Load() != 0 {
		t.Fatalf("CAS results: successes=%d conflicts=%d unexpected=%d", successes.Load(), conflicts.Load(), unexpected.Load())
	}
}

func newFixture(t *testing.T) *testFixture {
	t.Helper()
	root, err := localstate.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	keyState, err := localstate.Open(filepath.Join(root.Root(), "systems", testSystemID))
	if err != nil {
		t.Fatal(err)
	}
	key := seedBootstrapKey(t, keyState, "control-bootstrap", 1, 7, "")
	fixture := &testFixture{
		root: root, keyState: keyState,
		keys: sshkeys.NewManager(keyState, sshkeys.WithControlScope()), key: key, now: testTime,
	}
	manager, err := NewManager(root, fixture.keys, WithClock(func() time.Time { return fixture.now }))
	if err != nil {
		t.Fatal(err)
	}
	fixture.manager = manager
	fixture.input = BindInput{
		SystemID: testSystemID, Name: "control-1", Host: "control.example.test", SSHUser: "admin",
		OperatingSystem: OSDebian13, BootstrapKey: keyRef(key),
		HostPublicKey: testEd25519PublicKey(11, "provider-console host key"), EvidenceSource: EvidenceProviderConsole,
	}
	return fixture
}

func seedBootstrapKey(t *testing.T, state *localstate.Store, name string, generation uint64, seed byte, previous string) sshkeys.Record {
	return seedSSHKey(t, state, sshkeys.Bootstrap, name, generation, seed, previous)
}

func seedSSHKey(t *testing.T, state *localstate.Store, scope sshkeys.Scope, name string, generation uint64, seed byte, previous string) sshkeys.Record {
	t.Helper()
	publicKey := testEd25519PublicKey(seed, string(scope)+" "+name)
	normalized, fingerprint, err := sshkeys.ValidateEd25519PublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	record := sshkeys.Record{
		SchemaVersion: sshkeys.SchemaVersion, Scope: scope, Name: name, Generation: generation,
		Status: sshkeys.ActiveStatus, PublicKey: normalized, Fingerprint: fingerprint,
		PreviousFingerprint: previous, CreatedAt: testTime,
	}
	base := filepath.Join("keys", string(scope), name, "generations", generationDirectoryName(generation))
	if err := state.WriteFile(filepath.Join(base, "id_ed25519"), []byte("test-only private fixture\n")); err != nil {
		t.Fatal(err)
	}
	if err := state.WriteFile(filepath.Join(base, "id_ed25519.pub"), []byte(normalized+"\n")); err != nil {
		t.Fatal(err)
	}
	if err := state.WriteJSON(filepath.Join(base, "metadata.json"), record); err != nil {
		t.Fatal(err)
	}
	if err := state.WriteJSON(filepath.Join("keys", string(scope), name, "current.json"), record); err != nil {
		t.Fatal(err)
	}
	return record
}

func generationDirectoryName(generation uint64) string {
	const digits = "000000"
	value := []byte(digits)
	for index := len(value) - 1; generation > 0 && index >= 0; index-- {
		value[index] = byte('0' + generation%10)
		generation /= 10
	}
	return string(value)
}

func keyRef(record sshkeys.Record) BootstrapKeyRef {
	return BootstrapKeyRef{Scope: record.Scope, Name: record.Name, Generation: record.Generation, Fingerprint: record.Fingerprint}
}

func activateFixtureManagement(t *testing.T, fixture *testFixture, seed byte) (Record, sshkeys.Record) {
	t.Helper()
	bound, _, err := fixture.manager.Bind(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	management := seedSSHKey(t, fixture.keyState, sshkeys.Control, "control-management", 1, seed, "")
	fixture.now = fixture.now.Add(time.Minute)
	staged, changed, err := fixture.manager.Stage(
		bound.SystemID, bound.Name, bound.Revision, keyRef(management), ManagementAccessUser,
	)
	if err != nil || !changed {
		t.Fatalf("Stage fixture changed=%v, err=%v", changed, err)
	}
	if _, err := fixture.keys.Revoke(sshkeys.Bootstrap, fixture.key.Name); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Minute)
	activated, changed, err := fixture.manager.Activate(bound.SystemID, bound.Name, staged.Revision, ActivationConfirmation{
		ControlKey: keyRef(management), AccessUser: ManagementAccessUser,
		ManagementProofVerified: true, BootstrapRevocationVerified: true,
	})
	if err != nil || !changed {
		t.Fatalf("Activate fixture changed=%v, err=%v", changed, err)
	}
	return activated, management
}

func fingerprintFor(t *testing.T, publicKey string) string {
	t.Helper()
	_, fingerprint, err := sshkeys.ValidateEd25519PublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint
}

func assertNoPrivateStateJSON(t *testing.T, fixture *testFixture, record Record, materials ...AccessMaterial) {
	t.Helper()
	recordJSON, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{fixture.root.Root(), fixture.keyState.Root(), "id_ed25519", "test-only private fixture"} {
		if forbidden != "" && bytes.Contains(recordJSON, []byte(forbidden)) {
			t.Fatalf("control record JSON leaked private state %q: %s", forbidden, recordJSON)
		}
	}
	for _, material := range materials {
		encoded, err := json.Marshal(material)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{
			material.IdentityPath, material.KnownHostsPath,
			"IdentityPath", "KnownHostsPath", "identity_path", "known_hosts_path", "id_ed25519",
		} {
			if forbidden != "" && bytes.Contains(encoded, []byte(forbidden)) {
				t.Fatalf("access material JSON leaked private state %q: %s", forbidden, encoded)
			}
		}
	}
}

func testEd25519PublicKey(seed byte, comment string) string {
	blob := make([]byte, 0, 4+len("ssh-ed25519")+4+32)
	blob = appendSSHString(blob, []byte("ssh-ed25519"))
	key := make([]byte, 32)
	for index := range key {
		key[index] = seed + byte(index)
	}
	blob = appendSSHString(blob, key)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " " + comment
}

func appendSSHString(destination, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}

func assertMode(t *testing.T, path string, wanted os.FileMode, directory bool) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != wanted || info.IsDir() != directory {
		t.Fatalf("%s mode/type = %v", path, info.Mode())
	}
}
