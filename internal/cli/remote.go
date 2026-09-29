package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/release"
	"dynamicflow/internal/serving"
	"dynamicflow/internal/signing"
)

const remoteCAPath = "serving/remote-ca.pem"
const operatorReleaseHighWaterPath = "serving/release-high-water.json"

var remoteErrorCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var remoteReleaseSetID = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type operatorServingConfig struct {
	Schema        int       `json:"schema"`
	BaseURL       string    `json:"base_url"`
	TLSPin        string    `json:"tls_pin"`
	ReleaseSet    string    `json:"release_set"`
	ConfiguredAt  time.Time `json:"configured_at"`
	CACertificate string    `json:"ca_certificate"`
	ReleaseKeyID  string    `json:"release_key_id"`
	ControlKeyID  string    `json:"control_key_id"`
	DesiredKeyID  string    `json:"desired_key_id"`
}

type operatorReleaseHighWater struct {
	Schema     int    `json:"schema"`
	Generation uint64 `json:"generation"`
	SetID      string `json:"set_id"`
}

type remoteServing struct {
	config  operatorServingConfig
	baseURL *url.URL
	client  *http.Client
	control ed25519.PrivateKey
}

func commandServing(ctx *commandContext, args []string) int {
	if len(args) == 0 {
		return usage(ctx, "usage: flow serving <configure|show>")
	}
	switch args[0] {
	case "configure":
		flags := flag.NewFlagSet("serving configure", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		baseURL := flags.String("url", "", "serving HTTPS origin")
		caFile := flags.String("ca-file", "", "authenticated serving CA certificate")
		pin := flags.String("tls-pin", "", "authenticated SHA256 leaf certificate pin")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *baseURL == "" || !filepath.IsAbs(*caFile) || *pin == "" {
			return usage(ctx, "usage: flow serving configure --url https://HOST:PORT --ca-file ABS --tls-pin SHA256:BASE64")
		}
		return configureRemoteServing(ctx, *baseURL, *caFile, *pin)
	case "show":
		if len(args) != 1 {
			return usage(ctx, "usage: flow serving show")
		}
		config, _, err := loadOperatorServingConfig(ctx)
		if err != nil {
			return ctx.out.fail("config", err.Error(), "Run flow serving configure with an authenticated CA and TLS pin.", exitConfig)
		}
		return ctx.out.success("serving.show", config, fmt.Sprintf("Serving: %s\nTLS pin: %s\nRelease: %s", config.BaseURL, config.TLSPin, config.ReleaseSet))
	default:
		return usage(ctx, "unknown serving command: "+args[0])
	}
}

func configureRemoteServing(ctx *commandContext, value, caPath, pin string) int {
	base, err := parseServingOrigin(value)
	if err != nil {
		return ctx.out.fail("config", err.Error(), "Use one HTTPS origin without path, query or credentials.", exitConfig)
	}
	info, err := os.Lstat(caPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 1<<20 {
		return ctx.out.fail("tls", "CA path is not a safe regular file", "Copy the authenticated serving certificate to a local file and retry.", exitConfig)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return ctx.out.fail("tls", err.Error(), "Repair CA file permissions.", exitConfig)
	}
	client, err := newOperatorHTTPClient(base, caPEM, pin)
	if err != nil {
		return ctx.out.fail("tls", err.Error(), "Compare the pin with authenticated `flow start serving` output.", exitVerify)
	}
	releasePublicPath, _ := ctx.store.Path("keys/signing/release.public.pem")
	controlPublicPath, _ := ctx.store.Path("keys/signing/control.public.pem")
	desiredPublicPath, _ := ctx.store.Path("keys/signing/desired-state.public.pem")
	releasePublic, releaseErr := signing.LoadPublicFile(releasePublicPath)
	controlPublic, controlErr := signing.LoadPublicFile(controlPublicPath)
	desiredPublic, desiredErr := signing.LoadPublicFile(desiredPublicPath)
	if releaseErr != nil || controlErr != nil || desiredErr != nil {
		return ctx.out.fail("trust", "operator trust roots are incomplete", "Run flow init or restore the original keys.", exitAuth)
	}
	releaseKeyID, _ := signing.KeyID(releasePublic)
	controlKeyID, _ := signing.KeyID(controlPublic)
	desiredKeyID, _ := signing.KeyID(desiredPublic)
	if err := distinctSigningRoots(releaseKeyID, desiredKeyID, controlKeyID); err != nil {
		return ctx.out.fail("trust", err.Error(), "Restore three independent operator trust roots before contacting serving.", exitVerify)
	}
	ctx.out.phase("tls", "running", "verifying pinned serving identity")
	var health struct {
		Status       string `json:"status"`
		ReleaseSet   string `json:"release_set"`
		ReleaseKeyID string `json:"release_key_id"`
		DesiredKeyID string `json:"desired_key_id"`
		ControlKeyID string `json:"control_key_id"`
	}
	if err := publicRemoteJSON(context.Background(), client, base, http.MethodGet, "/v1/health", nil, http.StatusOK, &health); err != nil || health.Status != "ok" {
		return ctx.out.fail("serving", safeRemoteError(err), "Check serving status, URL, CA and TLS pin.", exitRemote)
	}
	var signed release.SignedManifest
	if err := publicRemoteJSON(context.Background(), client, base, http.MethodGet, "/v1/releases/current/manifest", nil, http.StatusOK, &signed); err != nil {
		return ctx.out.fail("release", safeRemoteError(err), "Serving did not return a bounded signed manifest.", exitVerify)
	}
	err = release.VerifyManifest(signed, releasePublic)
	if err != nil || signed.Manifest.SetID != health.ReleaseSet {
		return ctx.out.fail("release", "serving release signature or health binding failed", "Do not trust this serving node; verify release and trust roots.", exitVerify)
	}
	if health.ReleaseKeyID != releaseKeyID || health.DesiredKeyID != desiredKeyID || health.ControlKeyID != controlKeyID {
		return ctx.out.fail("trust", "serving trust-key IDs do not match this operator", "Do not enroll; reconcile serving with this operator's public keys.", exitVerify)
	}
	if err := acceptOperatorReleaseHighWater(ctx, signed.Manifest); err != nil {
		return ctx.out.fail("release_rollback", err.Error(), "Do not trust this serving node; restore a release at or above the operator high-water mark.", exitVerify)
	}
	if err := ctx.store.WriteFile(remoteCAPath, caPEM); err != nil {
		return ctx.out.fail("state", err.Error(), "Repair local state permissions.", exitConfig)
	}
	storedCA, _ := ctx.store.Path(remoteCAPath)
	config := operatorServingConfig{
		Schema: 1, BaseURL: strings.TrimSuffix(base.String(), "/"), TLSPin: pin,
		ReleaseSet: signed.Manifest.SetID, ConfiguredAt: time.Now().UTC(), CACertificate: storedCA,
		ReleaseKeyID: releaseKeyID, ControlKeyID: controlKeyID, DesiredKeyID: desiredKeyID,
	}
	if err := ctx.store.WriteJSON("serving/remote.json", config); err != nil {
		return ctx.out.fail("state", err.Error(), "Repair local state permissions.", exitConfig)
	}
	audit(ctx, "serving.configure", "success", map[string]any{"base_url": config.BaseURL, "release_set": config.ReleaseSet, "tls_pin": config.TLSPin})
	return ctx.out.success("serving.configure", config, fmt.Sprintf("Pinned serving %s\nTLS pin: %s\nVerified release: %s", config.BaseURL, config.TLSPin, config.ReleaseSet))
}

func acceptOperatorReleaseHighWater(ctx *commandContext, manifest release.Manifest) error {
	if ctx == nil || ctx.store == nil || manifest.Generation == 0 || !remoteReleaseSetID.MatchString(manifest.SetID) {
		return errors.New("invalid release high-water candidate")
	}
	return ctx.store.WithLock("serving/release-high-water.lock", func() error {
		var current operatorReleaseHighWater
		err := ctx.store.ReadJSON(operatorReleaseHighWaterPath, &current)
		switch {
		case err == nil:
			if current.Schema != 1 || current.Generation == 0 || !remoteReleaseSetID.MatchString(current.SetID) {
				return errors.New("invalid operator release high-water state")
			}
			if manifest.Generation < current.Generation {
				return fmt.Errorf("signed release generation %d is below pinned generation %d", manifest.Generation, current.Generation)
			}
			if manifest.Generation == current.Generation && manifest.SetID != current.SetID {
				return errors.New("signed release generation conflicts with the pinned set")
			}
			if manifest.Generation == current.Generation {
				return nil
			}
		case errors.Is(err, os.ErrNotExist):
		default:
			return err
		}
		return ctx.store.WriteJSON(operatorReleaseHighWaterPath, operatorReleaseHighWater{
			Schema: 1, Generation: manifest.Generation, SetID: manifest.SetID,
		})
	})
}

func loadRemoteServing(ctx *commandContext) (*remoteServing, error) {
	config, caPEM, err := loadOperatorServingConfig(ctx)
	if err != nil {
		return nil, err
	}
	base, err := parseServingOrigin(config.BaseURL)
	if err != nil {
		return nil, err
	}
	client, err := newOperatorHTTPClient(base, caPEM, config.TLSPin)
	if err != nil {
		return nil, err
	}
	controlPrivatePath, _ := ctx.store.Path("keys/signing/control.private.pem")
	controlPublicPath, _ := ctx.store.Path("keys/signing/control.public.pem")
	control, public, err := loadSigningPair(controlPrivatePath, controlPublicPath)
	if err != nil {
		return nil, err
	}
	keyID, _ := signing.KeyID(public)
	if keyID != config.ControlKeyID {
		return nil, errors.New("configured control key binding changed")
	}
	return &remoteServing{config: config, baseURL: base, client: client, control: control}, nil
}

func loadOperatorServingConfig(ctx *commandContext) (operatorServingConfig, []byte, error) {
	var config operatorServingConfig
	if err := ctx.store.ReadJSON("serving/remote.json", &config); err != nil {
		return config, nil, err
	}
	if config.Schema != 1 || config.BaseURL == "" || config.TLSPin == "" || !filepath.IsAbs(config.CACertificate) || config.ReleaseSet == "" ||
		config.ReleaseKeyID == "" || config.ControlKeyID == "" || config.DesiredKeyID == "" || config.ConfiguredAt.IsZero() {
		return config, nil, errors.New("invalid operator serving configuration")
	}
	if err := distinctSigningRoots(config.ReleaseKeyID, config.DesiredKeyID, config.ControlKeyID); err != nil {
		return config, nil, fmt.Errorf("invalid operator serving trust binding: %w", err)
	}
	expectedCA, _ := ctx.store.Path(remoteCAPath)
	if filepath.Clean(config.CACertificate) != expectedCA {
		return config, nil, errors.New("serving CA path escaped private state")
	}
	caPEM, err := ctx.store.ReadFile(remoteCAPath)
	return config, caPEM, err
}

func (remote *remoteServing) controlJSON(ctx context.Context, method, path string, input, output any, expected int) error {
	var body []byte
	var err error
	if input != nil {
		body, err = signing.CanonicalJSON(input)
		if err != nil {
			return err
		}
	}
	signed, err := enrollment.NewSignedControlRequest(remote.control, method, path, body, time.Now().UTC())
	if err != nil {
		return err
	}
	authorization, err := serving.EncodeControlAuthorization(signed)
	if err != nil {
		return err
	}
	return remoteJSON(ctx, remote.client, remote.baseURL, method, path, body, authorization, expected, output)
}

func (remote *remoteServing) controlReleaseBundle(ctx context.Context, file *os.File, size int64, digest string, output any) error {
	const path = "/v1/admin/releases/import"
	if ctx == nil || file == nil || size <= 0 {
		return errors.New("invalid release bundle upload")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return errors.New("release bundle upload file is unsafe")
	}
	signed, err := enrollment.NewSignedControlRequestDigest(remote.control, http.MethodPost, path, digest, time.Now().UTC())
	if err != nil {
		return err
	}
	authorization, err := serving.EncodeControlAuthorization(signed)
	if err != nil {
		return err
	}
	target := *remote.baseURL
	target.Path = path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), io.NewSectionReader(file, 0, size))
	if err != nil {
		return err
	}
	request.ContentLength = size
	request.GetBody = nil
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Content-Type", release.BundleMediaType)
	request.Header.Set("User-Agent", "dynamicflow-operator/1")
	request.Header.Set(serving.ControlAuthorizationHeader, authorization)
	uploadClient := *remote.client
	uploadClient.Timeout = 2 * time.Hour
	response, err := uploadClient.Do(request)
	if err != nil {
		return err
	}
	return decodeRemoteJSONResponse(response, http.StatusCreated, output)
}

func (remote *remoteServing) publicJSON(ctx context.Context, method, path string, output any) error {
	return publicRemoteJSON(ctx, remote.client, remote.baseURL, method, path, nil, http.StatusOK, output)
}

func publicRemoteJSON(ctx context.Context, client *http.Client, base *url.URL, method, path string, body []byte, expected int, output any) error {
	return remoteJSON(ctx, client, base, method, path, body, "", expected, output)
}

func remoteJSON(ctx context.Context, client *http.Client, base *url.URL, method, path string, body []byte, authorization string, expected int, output any) error {
	if ctx == nil || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\r\n\x00") {
		return errors.New("invalid serving request path")
	}
	target := *base
	target.Path = path
	request, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.GetBody = nil
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("User-Agent", "dynamicflow-operator/1")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		request.Header.Set(serving.ControlAuthorizationHeader, authorization)
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	return decodeRemoteJSONResponse(response, expected, output)
}

func decodeRemoteJSONResponse(response *http.Response, expected int, output any) error {
	if response == nil {
		return errors.New("serving returned no response")
	}
	defer response.Body.Close()
	const limit = int64(2 << 20)
	if response.ContentLength > limit {
		return errors.New("serving response exceeded size limit")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || len(data) > int(limit) {
		return errors.New("serving response exceeded size limit")
	}
	if response.StatusCode != expected {
		return &operatorHTTPError{Status: response.StatusCode, Code: extractRemoteErrorCode(data)}
	}
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return errors.New("serving response was not JSON")
	}
	if output == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("invalid serving JSON response")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("serving JSON response had trailing content")
	}
	return nil
}

type operatorHTTPError struct {
	Status int
	Code   string
}

func (err *operatorHTTPError) Error() string {
	if err.Code == "" {
		return fmt.Sprintf("serving returned HTTP %d", err.Status)
	}
	return fmt.Sprintf("serving returned HTTP %d (%s)", err.Status, err.Code)
}

func extractRemoteErrorCode(data []byte) string {
	var value struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &value) == nil && remoteErrorCode.MatchString(value.Error.Code) {
		return value.Error.Code
	}
	return ""
}

func safeRemoteError(err error) string {
	if err == nil {
		return "serving health was not ok"
	}
	var remote *operatorHTTPError
	if errors.As(err, &remote) {
		return remote.Error()
	}
	return "serving connection or verification failed"
}

func parseServingOrigin(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("serving URL must be one HTTPS origin")
	}
	parsed.Path, parsed.RawPath = "", ""
	return parsed, nil
}

func newOperatorHTTPClient(base *url.URL, caPEM []byte, pin string) (*http.Client, error) {
	block, rest := pemDecodeCertificate(caPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected exactly one CA certificate")
	}
	certificate, err := x509.ParseCertificate(block)
	if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid {
		return nil, errors.New("invalid serving CA certificate")
	}
	expectedPin, err := parseOperatorPin(pin)
	if err != nil {
		return nil, err
	}
	if digest := sha256.Sum256(certificate.Raw); subtle.ConstantTimeCompare(digest[:], expectedPin) != 1 {
		return nil, errors.New("serving CA does not match TLS pin")
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: base.Hostname(),
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return errors.New("serving TLS chain is not the pinned leaf")
			}
			digest := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(digest[:], expectedPin) != 1 {
				return errors.New("serving TLS pin mismatch")
			}
			return nil
		},
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true, MaxIdleConns: 4,
		MaxIdleConnsPerHost: 2, MaxConnsPerHost: 4, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 32 << 10,
		DisableCompression: true, TLSClientConfig: tlsConfig,
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}, nil
}

func pemDecodeCertificate(data []byte) ([]byte, []byte) {
	// kept local to avoid accepting additional PEM blocks through CertPool.
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, rest
	}
	return block.Bytes, rest
}

func parseOperatorPin(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "SHA256:") {
		return nil, errors.New("TLS pin must use SHA256:base64 format")
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "SHA256:"))
	if err != nil || len(decoded) != sha256.Size || value != "SHA256:"+base64.RawStdEncoding.EncodeToString(decoded) {
		return nil, errors.New("invalid TLS certificate pin")
	}
	return decoded, nil
}
