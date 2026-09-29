package instanceclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"dynamicflow/internal/release"
)

const immutableReleasePathPrefix = "/v1/releases/sets/"

var ErrArtifactNotBound = errors.New("artifact is not bound to the verified release manifest")

// DownloadArtifact streams one immutable artifact into destination. the caller
// must provide the exact component from signed; accepting a bare URL or logical
// path here would turn the pinned HTTPS client into a confused deputy.

// the release signature, exact component binding, response size, and SHA-256
// digest are all verified. destination may therefore contain incomplete or
// rejected bytes when this method returns an error. callers that write durable
// files must write to a private temporary file and activate it only after a nil
// result. DownloadArtifact never closes, truncates, renames, or removes caller
// resources.
func (client *Client) DownloadArtifact(
	ctx context.Context,
	signed release.SignedManifest,
	component release.Component,
	destination io.Writer,
) error {
	client.mu.Lock()
	defer client.mu.Unlock()

	if err := client.ensureOpenLocked(); err != nil {
		return err
	}
	if ctx == nil || destination == nil {
		return ErrInvalidConfig
	}
	if err := release.VerifyManifest(signed, client.releasePublicKey); err != nil {
		return err
	}
	if !manifestContainsComponent(signed.Manifest, component) {
		return ErrArtifactNotBound
	}

	artifactPath, err := immutableReleaseArtifactPath(signed.Manifest.SetID, component.Artifact)
	if err != nil {
		return err
	}
	target := *client.baseURL
	target.Path = artifactPath
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	target.ForceQuery = false
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return fmt.Errorf("create artifact request: %w", err)
	}
	// this endpoint is public after TLS and release-signature verification. Do
	// not attach the instance authorization header (or any enrollment material).
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("User-Agent", "dynamicflow-instance/1")

	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("artifact request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return boundedArtifactHTTPError(response)
	}
	if !isArtifactContentType(response.Header.Get("Content-Type")) ||
		!isIdentityContentEncoding(response.Header.Get("Content-Encoding")) {
		return ErrUnexpectedResponse
	}
	if response.ContentLength >= 0 && response.ContentLength != component.Size {
		return fmt.Errorf("%w: artifact content length differs from signed size", release.ErrArtifactTampered)
	}

	digest := sha256.New()
	tracked := &artifactDestination{writer: destination}
	written, copyErr := io.CopyN(io.MultiWriter(tracked, digest), response.Body, component.Size)
	if copyErr != nil {
		if tracked.err != nil {
			return fmt.Errorf("write artifact destination: %w", tracked.err)
		}
		return fmt.Errorf("%w: artifact ended after %d of %d bytes: %v", release.ErrArtifactTampered, written, component.Size, copyErr)
	}

	var extra [1]byte
	extraBytes, completionErr := io.ReadFull(response.Body, extra[:])
	if extraBytes != 0 {
		return fmt.Errorf("%w: artifact exceeds signed size", release.ErrArtifactTampered)
	}
	if completionErr != nil && !errors.Is(completionErr, io.EOF) {
		return fmt.Errorf("%w: artifact response did not terminate cleanly: %v", release.ErrArtifactTampered, completionErr)
	}
	actualDigest := "sha256:" + hex.EncodeToString(digest.Sum(nil))
	if actualDigest != component.Digest {
		return fmt.Errorf("%w: artifact digest differs from signed digest", release.ErrArtifactTampered)
	}
	return nil
}

func immutableReleaseManifestPath(setID string) (string, error) {
	setName, err := canonicalReleaseSetName(setID)
	if err != nil {
		return "", err
	}
	return immutableReleasePathPrefix + setName + "/manifest", nil
}

func immutableReleaseArtifactPath(setID, logical string) (string, error) {
	setName, err := canonicalReleaseSetName(setID)
	if err != nil {
		return "", err
	}
	if logical == "" || strings.ContainsAny(logical, "?#\r\n\x00") || strings.HasPrefix(logical, "/") {
		return "", ErrArtifactNotBound
	}
	return immutableReleasePathPrefix + setName + "/artifacts/" + logical, nil
}

func canonicalReleaseSetName(setID string) (string, error) {
	if len(setID) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(setID, "sha256:") {
		return "", ErrArtifactNotBound
	}
	setName := strings.TrimPrefix(setID, "sha256:")
	decoded, err := hex.DecodeString(setName)
	if err != nil || len(decoded) != sha256.Size || setName != strings.ToLower(setName) {
		return "", ErrArtifactNotBound
	}
	return setName, nil
}

func manifestContainsComponent(manifest release.Manifest, expected release.Component) bool {
	for _, component := range manifest.Components {
		if component == expected {
			return true
		}
	}
	return false
}

func isArtifactContentType(value string) bool {
	contentType, _, err := mime.ParseMediaType(value)
	return err == nil && contentType == "application/octet-stream"
}

func isIdentityContentEncoding(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || strings.EqualFold(value, "identity")
}

func boundedArtifactHTTPError(response *http.Response) error {
	if response.ContentLength > maxErrorBody {
		return &HTTPError{StatusCode: response.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxErrorBody+1))
	if err != nil || len(body) > maxErrorBody {
		clearBytes(body)
		return &HTTPError{StatusCode: response.StatusCode}
	}
	code := safeErrorCode(body)
	clearBytes(body)
	return &HTTPError{StatusCode: response.StatusCode, Code: code}
}

// artifactDestination records whether io.CopyN stopped because the caller's
// writer failed. this preserves that error instead of misclassifying it as a
// truncated network response.
type artifactDestination struct {
	writer io.Writer
	err    error
}

func (destination *artifactDestination) Write(data []byte) (int, error) {
	written, err := destination.writer.Write(data)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil && destination.err == nil {
		destination.err = err
	}
	return written, err
}
