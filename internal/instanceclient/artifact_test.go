package instanceclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"dynamicflow/internal/release"
	"dynamicflow/internal/serving"
	"dynamicflow/internal/signing"
)

type artifactTestRequest struct {
	method        string
	path          string
	rawQuery      string
	authorization string
	contentLength int64
	body          []byte
	header        http.Header
}

type artifactTestFixture struct {
	client    *Client
	signed    release.SignedManifest
	component release.Component
	content   []byte

	requestsMu sync.Mutex
	requests   []artifactTestRequest
}

type artifactTestResponder func(http.ResponseWriter, *http.Request, *artifactTestFixture)

func TestDownloadArtifactStreamsVerifiedPublicArtifact(t *testing.T) {
	content := bytes.Repeat([]byte("immutable-artifact-block\n"), 4096)
	fixture := newArtifactTestFixture(t, content, nil)
	var destination closeTrackingArtifactWriter
	if err := fixture.client.DownloadArtifact(context.Background(), fixture.signed, fixture.component, &destination); err != nil {
		t.Fatalf("download artifact: %v", err)
	}
	if !bytes.Equal(destination.Bytes(), content) {
		t.Fatalf("downloaded artifact mismatch: got %d bytes, want %d", destination.Len(), len(content))
	}
	if destination.closed {
		t.Fatal("downloader closed a caller-owned writer")
	}

	requests := fixture.capturedRequests()
	if len(requests) != 1 {
		t.Fatalf("request count = %d, want 1", len(requests))
	}
	request := requests[0]
	wantPath, err := immutableReleaseArtifactPath(fixture.signed.Manifest.SetID, fixture.component.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	if request.method != http.MethodGet || request.path != wantPath || request.rawQuery != "" ||
		request.authorization != "" || request.contentLength != 0 || len(request.body) != 0 {
		t.Fatalf("unsafe artifact request: %+v", request)
	}
	if request.header.Get("Accept") != "application/octet-stream" || request.header.Get("Cookie") != "" ||
		request.header.Get("Proxy-Authorization") != "" || request.header.Get(serving.AuthorizationHeader) != "" {
		t.Fatalf("unexpected artifact request headers: %#v", request.header)
	}
	for name, values := range request.header {
		for _, value := range values {
			if strings.Contains(strings.ToLower(name+":"+value), "enrollment") || strings.Contains(value, "test-secret") {
				t.Fatalf("credential-like data escaped in request header %q", name)
			}
		}
	}
}

func TestDownloadArtifactRejectsTruncationOversizeAndDigestMismatch(t *testing.T) {
	content := []byte("exact signed artifact bytes")
	tests := []struct {
		name              string
		responder         artifactTestResponder
		wantWrittenLength int
	}{
		{
			name: "truncated",
			responder: func(writer http.ResponseWriter, _ *http.Request, fixture *artifactTestFixture) {
				writeArtifactTestResponse(writer, fixture.content[:len(fixture.content)-1], int64(len(fixture.content)), false, "application/octet-stream", "")
			},
			wantWrittenLength: len(content) - 1,
		},
		{
			name: "undersized content length",
			responder: func(writer http.ResponseWriter, _ *http.Request, fixture *artifactTestFixture) {
				body := fixture.content[:len(fixture.content)-1]
				writeArtifactTestResponse(writer, body, int64(len(body)), false, "application/octet-stream", "")
			},
			wantWrittenLength: 0,
		},
		{
			name: "oversized content length",
			responder: func(writer http.ResponseWriter, _ *http.Request, fixture *artifactTestFixture) {
				body := append(append([]byte(nil), fixture.content...), '!')
				writeArtifactTestResponse(writer, body, int64(len(body)), false, "application/octet-stream", "")
			},
			wantWrittenLength: 0,
		},
		{
			name: "oversized unknown length body",
			responder: func(writer http.ResponseWriter, _ *http.Request, fixture *artifactTestFixture) {
				body := append(append([]byte(nil), fixture.content...), '!')
				writeArtifactTestResponse(writer, body, -1, true, "application/octet-stream", "")
			},
			wantWrittenLength: len(content),
		},
		{
			name: "wrong digest",
			responder: func(writer http.ResponseWriter, _ *http.Request, fixture *artifactTestFixture) {
				body := append([]byte(nil), fixture.content...)
				body[0] ^= 0xff
				writeArtifactTestResponse(writer, body, int64(len(body)), false, "application/octet-stream", "")
			},
			wantWrittenLength: len(content),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newArtifactTestFixture(t, content, test.responder)
			var destination bytes.Buffer
			err := fixture.client.DownloadArtifact(context.Background(), fixture.signed, fixture.component, &destination)
			if !errors.Is(err, release.ErrArtifactTampered) {
				t.Fatalf("error = %v, want artifact tamper", err)
			}
			if destination.Len() != test.wantWrittenLength {
				t.Fatalf("destination length = %d, want %d", destination.Len(), test.wantWrittenLength)
			}
		})
	}
}

func TestDownloadArtifactRejectsRedirectWithoutFollowing(t *testing.T) {
	fixture := newArtifactTestFixture(t, []byte("signed artifact"), func(writer http.ResponseWriter, request *http.Request, fixture *artifactTestFixture) {
		wantPath, _ := immutableReleaseArtifactPath(fixture.signed.Manifest.SetID, fixture.component.Artifact)
		if request.URL.Path == wantPath {
			http.Redirect(writer, request, "/redirect-target?credential=must-not-follow", http.StatusFound)
			return
		}
		writeArtifactTestResponse(writer, fixture.content, int64(len(fixture.content)), false, "application/octet-stream", "")
	})
	var destination bytes.Buffer
	err := fixture.client.DownloadArtifact(context.Background(), fixture.signed, fixture.component, &destination)
	var responseError *HTTPError
	if !errors.As(err, &responseError) || responseError.StatusCode != http.StatusFound {
		t.Fatalf("error = %v, want HTTP 302", err)
	}
	if requests := fixture.capturedRequests(); len(requests) != 1 {
		t.Fatalf("redirect was followed: captured %d requests", len(requests))
	}
	if destination.Len() != 0 {
		t.Fatal("redirect response wrote artifact bytes")
	}
}

func TestDownloadArtifactRejectsUnboundComponentAndTamperedManifestBeforeRequest(t *testing.T) {
	fixture := newArtifactTestFixture(t, []byte("signed artifact"), nil)
	component := fixture.component
	component.Artifact = "pbp/v0.1.8/linux-amd64/../../credential"
	if err := fixture.client.DownloadArtifact(context.Background(), fixture.signed, component, io.Discard); !errors.Is(err, ErrArtifactNotBound) {
		t.Fatalf("unbound path error = %v", err)
	}

	tampered := fixture.signed
	tampered.Manifest.Components = append([]release.Component(nil), tampered.Manifest.Components...)
	tampered.Manifest.Components[0].Digest = "sha256:" + strings.Repeat("0", 64)
	if err := fixture.client.DownloadArtifact(context.Background(), tampered, tampered.Manifest.Components[0], io.Discard); err == nil {
		t.Fatal("tampered manifest was accepted")
	}
	if requests := fixture.capturedRequests(); len(requests) != 0 {
		t.Fatalf("invalid binding reached network: %d requests", len(requests))
	}
}

func TestDownloadArtifactRejectsResponseFailureAndBoundsErrorBody(t *testing.T) {
	t.Run("safe API error", func(t *testing.T) {
		fixture := newArtifactTestFixture(t, []byte("signed artifact"), func(writer http.ResponseWriter, _ *http.Request, _ *artifactTestFixture) {
			body := []byte(`{"error":{"code":"release_unavailable","message":"private response detail"}}`)
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write(body)
		})
		var destination bytes.Buffer
		err := fixture.client.DownloadArtifact(context.Background(), fixture.signed, fixture.component, &destination)
		var responseError *HTTPError
		if !errors.As(err, &responseError) || responseError.StatusCode != http.StatusServiceUnavailable || responseError.Code != "release_unavailable" {
			t.Fatalf("error = %v, want bounded release_unavailable HTTP error", err)
		}
		if strings.Contains(err.Error(), "private response detail") || destination.Len() != 0 {
			t.Fatalf("untrusted response escaped: error=%q bytes=%d", err, destination.Len())
		}
	})

	t.Run("oversized API error", func(t *testing.T) {
		fixture := newArtifactTestFixture(t, []byte("signed artifact"), func(writer http.ResponseWriter, _ *http.Request, _ *artifactTestFixture) {
			body := bytes.Repeat([]byte("x"), maxErrorBody+1024)
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
			writer.WriteHeader(http.StatusInternalServerError)
			_, _ = writer.Write(body)
		})
		err := fixture.client.DownloadArtifact(context.Background(), fixture.signed, fixture.component, io.Discard)
		var responseError *HTTPError
		if !errors.As(err, &responseError) || responseError.StatusCode != http.StatusInternalServerError || responseError.Code != "" {
			t.Fatalf("error = %v, want body-free HTTP 500", err)
		}
	})
}

func TestDownloadArtifactPreservesWriterFailure(t *testing.T) {
	fixture := newArtifactTestFixture(t, bytes.Repeat([]byte("a"), 4096), nil)
	sentinel := errors.New("destination unavailable")
	destination := &failingArtifactWriter{remaining: 37, err: sentinel}
	err := fixture.client.DownloadArtifact(context.Background(), fixture.signed, fixture.component, destination)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want destination failure", err)
	}
	if errors.Is(err, release.ErrArtifactTampered) {
		t.Fatalf("writer failure was misclassified as tamper: %v", err)
	}
	if destination.written != 37 {
		t.Fatalf("writer received %d bytes, want 37", destination.written)
	}
}

func TestDownloadArtifactRejectsUnexpectedRepresentationBeforeWriting(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		encoding    string
	}{
		{name: "HTML MIME", contentType: "text/html"},
		{name: "compressed encoding", contentType: "application/octet-stream", encoding: "gzip"},
		{name: "missing MIME"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newArtifactTestFixture(t, []byte("signed artifact"), func(writer http.ResponseWriter, _ *http.Request, fixture *artifactTestFixture) {
				writeArtifactTestResponse(writer, fixture.content, int64(len(fixture.content)), false, test.contentType, test.encoding)
			})
			var destination bytes.Buffer
			err := fixture.client.DownloadArtifact(context.Background(), fixture.signed, fixture.component, &destination)
			if !errors.Is(err, ErrUnexpectedResponse) || destination.Len() != 0 {
				t.Fatalf("error=%v destination=%d, want rejected representation", err, destination.Len())
			}
		})
	}
}

func TestDownloadArtifactConcurrentCallsRaceSafe(t *testing.T) {
	fixture := newArtifactTestFixture(t, bytes.Repeat([]byte("race-safe-artifact\n"), 256), nil)
	const workers = 8
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			var destination bytes.Buffer
			if err := fixture.client.DownloadArtifact(context.Background(), fixture.signed, fixture.component, &destination); err != nil {
				errorsByWorker <- err
				return
			}
			if !bytes.Equal(destination.Bytes(), fixture.content) {
				errorsByWorker <- fmt.Errorf("artifact content mismatch")
			}
		}()
	}
	wait.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		t.Error(err)
	}
	if requests := fixture.capturedRequests(); len(requests) != workers {
		t.Fatalf("request count = %d, want %d", len(requests), workers)
	}
}

func newArtifactTestFixture(t *testing.T, content []byte, responder artifactTestResponder) *artifactTestFixture {
	t.Helper()
	root := t.TempDir()
	releasePublic, releasePrivate, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	desiredPublic, _, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "artifact.tar.gz")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := release.BuildFromArtifacts(9, []release.ArtifactInput{{
		Component: "pbp", Version: "v0.1.8", Target: "linux-amd64", ArtifactName: "artifact.tar.gz", SourcePath: source,
	}}, []release.Profile{{Name: "pbp", Components: []string{"pbp"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := release.SignManifest(manifest, releasePrivate)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &artifactTestFixture{
		signed: signed, component: manifest.Components[0], content: append([]byte(nil), content...),
	}
	if responder == nil {
		responder = func(writer http.ResponseWriter, request *http.Request, fixture *artifactTestFixture) {
			wantPath, _ := immutableReleaseArtifactPath(fixture.signed.Manifest.SetID, fixture.component.Artifact)
			if request.URL.Path != wantPath {
				http.NotFound(writer, request)
				return
			}
			writeArtifactTestResponse(writer, fixture.content, int64(len(fixture.content)), false, "application/octet-stream", "")
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	server, caPEM, pin := startPinnedTLSServer(t, now, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(request.Body, 64))
		fixture.requestsMu.Lock()
		fixture.requests = append(fixture.requests, artifactTestRequest{
			method: request.Method, path: request.URL.Path, rawQuery: request.URL.RawQuery,
			authorization: request.Header.Get(serving.AuthorizationHeader), contentLength: request.ContentLength,
			body: append([]byte(nil), body...), header: request.Header.Clone(),
		})
		fixture.requestsMu.Unlock()
		responder(writer, request, fixture)
	}))
	client, err := New(Config{
		StateDir: filepath.Join(root, "state"), BaseURL: server.URL, CACertificatePEM: caPEM, TLSPin: pin,
		DesiredPublicKey: desiredPublic, ReleasePublicKey: releasePublic,
		Instance: "artifact-01", Profile: "pbp", RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.client = client
	t.Cleanup(func() { _ = client.Close() })
	return fixture
}

func (fixture *artifactTestFixture) capturedRequests() []artifactTestRequest {
	fixture.requestsMu.Lock()
	defer fixture.requestsMu.Unlock()
	return append([]artifactTestRequest(nil), fixture.requests...)
}

func writeArtifactTestResponse(writer http.ResponseWriter, body []byte, contentLength int64, flush bool, contentType, contentEncoding string) {
	if contentType != "" {
		writer.Header().Set("Content-Type", contentType)
	}
	if contentEncoding != "" {
		writer.Header().Set("Content-Encoding", contentEncoding)
	}
	if contentLength >= 0 {
		writer.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	}
	writer.WriteHeader(http.StatusOK)
	if flush {
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	_, _ = writer.Write(body)
}

type failingArtifactWriter struct {
	remaining int
	written   int
	err       error
}

type closeTrackingArtifactWriter struct {
	bytes.Buffer
	closed bool
}

func (writer *closeTrackingArtifactWriter) Close() error {
	writer.closed = true
	return nil
}

func (writer *failingArtifactWriter) Write(data []byte) (int, error) {
	if writer.remaining <= 0 {
		return 0, writer.err
	}
	if len(data) > writer.remaining {
		written := writer.remaining
		writer.remaining = 0
		writer.written += written
		return written, writer.err
	}
	writer.remaining -= len(data)
	writer.written += len(data)
	return len(data), nil
}
