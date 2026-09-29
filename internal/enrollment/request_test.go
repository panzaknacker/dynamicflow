package enrollment

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/signing"
)

func TestSignedInstanceRequestTamperStaleAndPersistentReplay(t *testing.T) {
	publicKey, privateKey, _ := testIdentity(t)
	otherPublic, _, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	path := testStorePath(t)
	store, err := NewStore(path, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"status":"ready"}`)
	signed, err := NewSignedInstanceRequest(privateKey, "vm-01", "post", "/v1/instances/vm-01/status", body, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyInstanceRequest(signed, publicKey, "vm-01", "POST", signed.Request.Path, []byte("other"), time.Minute); !errors.Is(err, ErrBinding) {
		t.Fatalf("wrong body: got %v, want ErrBinding", err)
	}
	if err := store.VerifyInstanceRequest(signed, otherPublic, "vm-01", "POST", signed.Request.Path, body, time.Minute); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("wrong public key: got %v, want invalid signature", err)
	}
	if err := store.VerifyInstanceRequest(signed, publicKey, "vm-01", "POST", signed.Request.Path, body, time.Minute); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	reopened, err := NewStore(path, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.VerifyInstanceRequest(signed, publicKey, "vm-01", "POST", signed.Request.Path, body, time.Minute); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay after reopen: got %v, want ErrReplay", err)
	}

	tampered, err := NewSignedInstanceRequest(privateKey, "vm-01", "POST", "/v1/instances/vm-01/status", body, now)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Request.Path = "/v1/instances/vm-01/desired"
	if err := store.VerifyInstanceRequest(tampered, publicKey, "vm-01", "POST", tampered.Request.Path, body, time.Minute); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("tampered path: got %v, want invalid signature", err)
	}
	stale, err := NewSignedInstanceRequest(privateKey, "vm-01", "POST", "/v1/instances/vm-01/status", body, now.Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyInstanceRequest(stale, publicKey, "vm-01", "POST", stale.Request.Path, body, time.Minute); !errors.Is(err, ErrStaleRequest) {
		t.Fatalf("stale request: got %v, want ErrStaleRequest", err)
	}
}

func TestConcurrentSignedRequestAcceptedOnceAcrossStores(t *testing.T) {
	publicKey, privateKey, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	path := testStorePath(t)
	body := []byte(`{"healthy":true}`)
	signed, err := NewSignedInstanceRequest(privateKey, "vm-01", "PUT", "/v1/instances/vm-01/status", body, now)
	if err != nil {
		t.Fatal(err)
	}
	const callers = 24
	stores := make([]*Store, callers)
	for index := range stores {
		stores[index], err = NewStore(path, WithClock(func() time.Time { return now }))
		if err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make(chan error, callers)
	var group sync.WaitGroup
	for _, candidate := range stores {
		group.Add(1)
		go func(store *Store) {
			defer group.Done()
			<-start
			results <- store.VerifyInstanceRequest(signed, publicKey, "vm-01", "PUT", signed.Request.Path, body, time.Minute)
		}(candidate)
	}
	close(start)
	group.Wait()
	close(results)
	successes := 0
	replays := 0
	for result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, ErrReplay):
			replays++
		default:
			t.Fatalf("unexpected result: %v", result)
		}
	}
	if successes != 1 || replays != callers-1 {
		t.Fatalf("successes=%d replays=%d", successes, replays)
	}
}

func TestSignedControlRequestExactBindingAndPersistentReplay(t *testing.T) {
	publicKey, privateKey, _ := testIdentity(t)
	otherPublic, _, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	path := testStorePath(t)
	store, err := NewStore(path, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"desired":{"generation":2}}`)
	requestPath := "/v1/admin/instances/vm-01/desired"
	signed, err := NewSignedControlRequest(privateKey, "PUT", requestPath, body, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyControlRequest(signed, publicKey, "POST", requestPath, body, time.Minute); !errors.Is(err, ErrBinding) {
		t.Fatalf("wrong method: got %v, want ErrBinding", err)
	}
	if err := store.VerifyControlRequest(signed, publicKey, "PUT", requestPath+"-other", body, time.Minute); !errors.Is(err, ErrBinding) {
		t.Fatalf("wrong path: got %v, want ErrBinding", err)
	}
	if err := store.VerifyControlRequest(signed, publicKey, "PUT", requestPath, append(body, ' '), time.Minute); !errors.Is(err, ErrBinding) {
		t.Fatalf("wrong body: got %v, want ErrBinding", err)
	}
	if err := store.VerifyControlRequest(signed, otherPublic, "PUT", requestPath, body, time.Minute); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("wrong control key: got %v, want invalid signature", err)
	}
	if err := signing.VerifyCanonical(publicKey, InstanceRequestDomain, signed.Request, signed.Signature); !errors.Is(err, signing.ErrInvalidSignature) {
		t.Fatalf("control signature verified in instance domain: %v", err)
	}
	if err := store.VerifyControlRequest(signed, publicKey, "PUT", requestPath, body, time.Minute); err != nil {
		t.Fatalf("first control verification: %v", err)
	}
	reopened, err := NewStore(path, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.VerifyControlRequest(signed, publicKey, "PUT", requestPath, body, time.Minute); !errors.Is(err, ErrReplay) {
		t.Fatalf("control replay after reopen: got %v, want ErrReplay", err)
	}
	stale, err := NewSignedControlRequest(privateKey, "GET", "/v1/admin/enrollments", nil, now.Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.VerifyControlRequest(stale, publicKey, "GET", "/v1/admin/enrollments", nil, time.Minute); !errors.Is(err, ErrStaleRequest) {
		t.Fatalf("stale control request: got %v, want ErrStaleRequest", err)
	}
}

func TestConcurrentControlRequestAcceptedOnceAcrossStores(t *testing.T) {
	publicKey, privateKey, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	path := testStorePath(t)
	body := []byte(`{"operation":"apply"}`)
	requestPath := "/v1/admin/instances/vm-01/desired"
	signed, err := NewSignedControlRequest(privateKey, "PUT", requestPath, body, now)
	if err != nil {
		t.Fatal(err)
	}
	const callers = 24
	stores := make([]*Store, callers)
	for index := range stores {
		stores[index], err = NewStore(path, WithClock(func() time.Time { return now }))
		if err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make(chan error, callers)
	var group sync.WaitGroup
	for _, candidate := range stores {
		group.Add(1)
		go func(store *Store) {
			defer group.Done()
			<-start
			results <- store.VerifyControlRequest(signed, publicKey, "PUT", requestPath, body, time.Minute)
		}(candidate)
	}
	close(start)
	group.Wait()
	close(results)
	successes := 0
	replays := 0
	for result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, ErrReplay):
			replays++
		default:
			t.Fatalf("unexpected control verification result: %v", result)
		}
	}
	if successes != 1 || replays != callers-1 {
		t.Fatalf("successes=%d replays=%d", successes, replays)
	}
}

func TestControlAndInstanceNonceNamespacesDoNotCollide(t *testing.T) {
	instancePublic, instancePrivate, _ := testIdentity(t)
	controlPublic, controlPrivate, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	store, err := NewStore(testStorePath(t), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	nonce := fixedTestNonce(1)
	controlRequest := ControlRequest{
		Schema: ControlRequestSchema, Timestamp: now.Unix(), Nonce: nonce,
		Method: "GET", Path: "/v1/admin/enrollments", BodyDigest: bodyDigest(nil),
	}
	controlSignature, err := signing.SignCanonical(controlPrivate, ControlRequestDomain, controlRequest)
	if err != nil {
		t.Fatal(err)
	}
	instanceRequest := InstanceRequest{
		Schema: InstanceRequestSchema, Instance: "control", Timestamp: now.Unix(), Nonce: nonce,
		Method: "GET", Path: "/v1/instances/control/desired", BodyDigest: bodyDigest(nil),
	}
	instanceSignature, err := signing.SignCanonical(instancePrivate, InstanceRequestDomain, instanceRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyControlRequest(SignedControlRequest{Request: controlRequest, Signature: controlSignature}, controlPublic,
		"GET", controlRequest.Path, nil, time.Minute); err != nil {
		t.Fatalf("control request: %v", err)
	}
	if err := store.VerifyInstanceRequest(SignedInstanceRequest{Request: instanceRequest, Signature: instanceSignature}, instancePublic,
		"control", "GET", instanceRequest.Path, nil, time.Minute); err != nil {
		t.Fatalf("instance named control collided with control nonce namespace: %v", err)
	}
}

func TestLegacyInstanceNonceStillBlocksReplayAfterNamespaceMigration(t *testing.T) {
	publicKey, privateKey, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	store, err := NewStore(testStorePath(t), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"status":"ready"}`)
	signed, err := NewSignedInstanceRequest(privateKey, "vm-01", "POST", "/v1/instances/vm-01/status", body, now)
	if err != nil {
		t.Fatal(err)
	}
	err = store.withLockedState(true, func(state *diskState) (bool, error) {
		state.Nonces[signed.Request.Instance+"\x00"+signed.Request.Nonce] = now.Add(2 * time.Minute).Unix()
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyInstanceRequest(signed, publicKey, "vm-01", "POST", signed.Request.Path, body, time.Minute); !errors.Is(err, ErrReplay) {
		t.Fatalf("legacy nonce replay after migration: got %v, want ErrReplay", err)
	}
}

func TestLegacyControlNonceStillBlocksReplayAfterNamespaceMigration(t *testing.T) {
	publicKey, privateKey, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	store, err := NewStore(testStorePath(t), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := NewSignedControlRequest(privateKey, "GET", "/v1/admin/enrollments", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	err = store.withLockedState(true, func(state *diskState) (bool, error) {
		state.Nonces["control\x00"+signed.Request.Nonce] = now.Add(2 * time.Minute).Unix()
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyControlRequest(signed, publicKey, "GET", signed.Request.Path, nil, time.Minute); !errors.Is(err, ErrReplay) {
		t.Fatalf("legacy control nonce replay after migration: got %v, want ErrReplay", err)
	}
}

func TestControlReplayCacheCapacityFailsClosed(t *testing.T) {
	publicKey, privateKey, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	store, err := NewStore(testStorePath(t), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	err = store.withLockedState(true, func(state *diskState) (bool, error) {
		for index := 0; index < maxNonceCount; index++ {
			state.Nonces["control\x00"+fixedTestNonce(uint64(index))] = now.Add(time.Hour).Unix()
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := NewSignedControlRequest(privateKey, "GET", "/v1/admin/enrollments", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyControlRequest(signed, publicKey, "GET", signed.Request.Path, nil, time.Minute); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("full control replay cache: got %v, want ErrInvalidStore", err)
	}
}

func TestInstanceRequestFreshnessIsRecheckedAfterStoreLock(t *testing.T) {
	publicKey, privateKey, _ := testIdentity(t)
	issuedAt := time.Unix(1_800_000_000, 0).UTC()
	current := issuedAt
	store, err := NewStore(testStorePath(t), WithClock(func() time.Time {
		result := current
		current = issuedAt.Add(2 * time.Minute)
		return result
	}))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"status":"ready"}`)
	signed, err := NewSignedInstanceRequest(
		privateKey, "vm-01", "POST", "/v1/instances/vm-01/status", body, issuedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyInstanceRequest(
		signed, publicKey, "vm-01", "POST", signed.Request.Path, body, time.Minute,
	); !errors.Is(err, ErrStaleRequest) {
		t.Fatalf("request that expired while waiting for the store lock: got %v, want ErrStaleRequest", err)
	}
}

func TestControlRequestFreshnessIsRecheckedAfterStoreLock(t *testing.T) {
	publicKey, privateKey, _ := testIdentity(t)
	issuedAt := time.Unix(1_800_000_000, 0).UTC()
	current := issuedAt
	store, err := NewStore(testStorePath(t), WithClock(func() time.Time {
		result := current
		current = issuedAt.Add(2 * time.Minute)
		return result
	}))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := NewSignedControlRequest(privateKey, "GET", "/v1/admin/enrollments", nil, issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyControlRequest(
		signed, publicKey, "GET", signed.Request.Path, nil, time.Minute,
	); !errors.Is(err, ErrStaleRequest) {
		t.Fatalf("control request that expired while waiting for the store lock: got %v, want ErrStaleRequest", err)
	}
}

func TestReplayNonceSurvivesInclusiveFreshnessBoundary(t *testing.T) {
	publicKey, privateKey, _ := testIdentity(t)
	issuedAt := time.Unix(1_800_000_000, 0).UTC()
	current := issuedAt.Add(time.Minute)
	store, err := NewStore(testStorePath(t), WithClock(func() time.Time { return current }))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := NewSignedInstanceRequest(
		privateKey, "vm-01", "GET", "/v1/instances/vm-01/desired", nil, issuedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyInstanceRequest(
		signed, publicKey, "vm-01", "GET", signed.Request.Path, nil, time.Minute,
	); err != nil {
		t.Fatalf("first request at inclusive freshness boundary: %v", err)
	}
	if err := store.VerifyInstanceRequest(
		signed, publicKey, "vm-01", "GET", signed.Request.Path, nil, time.Minute,
	); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay at inclusive freshness boundary: got %v, want ErrReplay", err)
	}
}

func TestLegacyReplayNonceAtStoredExpiryRemainsBurned(t *testing.T) {
	publicKey, privateKey, _ := testIdentity(t)
	issuedAt := time.Unix(1_800_000_000, 0).UTC()
	current := issuedAt.Add(time.Minute)
	store, err := NewStore(testStorePath(t), WithClock(func() time.Time { return current }))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := NewSignedInstanceRequest(
		privateKey, "vm-01", "GET", "/v1/instances/vm-01/desired", nil, issuedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = store.withLockedState(true, func(state *diskState) (bool, error) {
		state.Nonces["instance\x00"+signed.Request.Instance+"\x00"+signed.Request.Nonce] = current.Unix()
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyInstanceRequest(
		signed, publicKey, "vm-01", "GET", signed.Request.Path, nil, time.Minute,
	); !errors.Is(err, ErrReplay) {
		t.Fatalf("legacy nonce at inclusive stored expiry: got %v, want ErrReplay", err)
	}
}

func fixedTestNonce(value uint64) string {
	buffer := make([]byte, 32)
	binary.BigEndian.PutUint64(buffer[len(buffer)-8:], value)
	return base64.RawURLEncoding.EncodeToString(buffer)
}
