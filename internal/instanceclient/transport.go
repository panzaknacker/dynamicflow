package instanceclient

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrTLSPin = errors.New("serving TLS certificate pin mismatch")

func parseBaseURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.ForceQuery {
		return nil, fmt.Errorf("%w: serving URL must be an HTTPS origin", ErrInvalidConfig)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, fmt.Errorf("%w: serving URL must not contain a path", ErrInvalidConfig)
	}
	parsed.Path = ""
	parsed.RawPath = ""
	return parsed, nil
}

func newHTTPClient(base *url.URL, caPEM []byte, pin string, timeout time.Duration) (*http.Client, *http.Transport, error) {
	certificate, err := parseSingleCertificate(caPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: explicit CA certificate: %v", ErrInvalidConfig, err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	expectedPin, err := parsePin(pin)
	if err != nil {
		return nil, nil, err
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: base.Hostname(),
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return ErrTLSPin
			}
			digest := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(digest[:], expectedPin) != 1 {
				return ErrTLSPin
			}
			return nil
		},
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    2,
		MaxConnsPerHost:        4,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  timeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 32 << 10,
		DisableCompression:     true,
		TLSClientConfig:        tlsConfig,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, transport, nil
}

func parseSingleCertificate(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected exactly one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if !certificate.IsCA || !certificate.BasicConstraintsValid {
		return nil, errors.New("certificate is not a CA")
	}
	return certificate, nil
}

func parsePin(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "SHA256:") {
		return nil, fmt.Errorf("%w: TLS pin must use SHA256:base64 format", ErrInvalidConfig)
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "SHA256:"))
	if err != nil || len(decoded) != sha256.Size || value != "SHA256:"+base64.RawStdEncoding.EncodeToString(decoded) {
		return nil, fmt.Errorf("%w: invalid TLS certificate pin", ErrInvalidConfig)
	}
	return decoded, nil
}
