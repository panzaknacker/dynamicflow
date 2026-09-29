// package servingruntime assembles the narrow HTTPS serving process from a
// root-created configuration containing only public trust material and a
// transport TLS key. release and desired-state private signing keys are never
// accepted by this package.
package servingruntime

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"dynamicflow/internal/enrollment"
	"dynamicflow/internal/release"
	"dynamicflow/internal/serving"
	"dynamicflow/internal/signing"
	"dynamicflow/internal/tlsutil"
)

const ConfigSchema = 1

type Config struct {
	Schema              int    `json:"schema"`
	Listen              string `json:"listen"`
	PublicURL           string `json:"public_url"`
	TLSCert             string `json:"tls_cert"`
	TLSKey              string `json:"tls_key"`
	ReleaseRoot         string `json:"release_root"`
	ReleasePublicKey    string `json:"release_public_key"`
	DesiredPublicKey    string `json:"desired_public_key"`
	ControlPublicKey    string `json:"control_public_key"`
	EnrollmentState     string `json:"enrollment_state"`
	DesiredStateDir     string `json:"desired_state_dir"`
	StatusDir           string `json:"status_dir"`
	LogDir              string `json:"log_dir"`
	AuditLog            string `json:"audit_log"`
	BootstrapScript     string `json:"bootstrap_script"`
	MaxClockSkewSeconds int64  `json:"max_clock_skew_seconds"`
}

func Load(path string) (Config, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return Config{}, errors.New("serving config path must be an absolute file")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 1<<20 || !securePrivateReadMode(info) {
		return Config{}, errors.New("serving config must be a regular mode 0600 file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode serving config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("serving config has trailing JSON")
	}
	if err := Validate(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func Validate(config Config) error {
	if config.Schema != ConfigSchema {
		return errors.New("unsupported serving config schema")
	}
	host, port, err := net.SplitHostPort(config.Listen)
	if err != nil || host == "" || port == "" || strings.ContainsAny(host, "\r\n\x00") {
		return errors.New("invalid serving listen address")
	}
	parsed, err := url.Parse(config.PublicURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return errors.New("public serving URL must be an HTTPS origin")
	}
	paths := []string{
		config.TLSCert, config.TLSKey, config.ReleaseRoot, config.ReleasePublicKey, config.DesiredPublicKey,
		config.ControlPublicKey, config.EnrollmentState, config.DesiredStateDir, config.StatusDir, config.AuditLog, config.BootstrapScript,
		config.LogDir,
	}
	seen := map[string]bool{}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) || strings.ContainsRune(path, '\x00') {
			return errors.New("serving paths must be absolute and must not name filesystem root")
		}
		clean := filepath.Clean(path)
		if seen[clean] {
			return errors.New("serving config paths must be distinct")
		}
		seen[clean] = true
	}
	if config.MaxClockSkewSeconds < 1 || config.MaxClockSkewSeconds > 3600 {
		return errors.New("serving clock skew must be between 1 and 3600 seconds")
	}
	return nil
}

// Run serves until ctx is cancelled. the caller should run this function as a
// dedicated unprivileged service account.
func Run(ctx context.Context, configPath string) error {
	config, err := Load(configPath)
	if err != nil {
		return err
	}
	for _, controlled := range []string{config.ReleasePublicKey, config.DesiredPublicKey, config.ControlPublicKey, config.BootstrapScript} {
		if err := requireRootControlledOrOwner(controlled); err != nil {
			return err
		}
	}
	releasePublic, err := signing.LoadPublicFile(config.ReleasePublicKey)
	if err != nil {
		return fmt.Errorf("load release public key: %w", err)
	}
	desiredPublic, err := signing.LoadPublicFile(config.DesiredPublicKey)
	if err != nil {
		return fmt.Errorf("load desired-state public key: %w", err)
	}
	controlPublic, err := signing.LoadPublicFile(config.ControlPublicKey)
	if err != nil {
		return fmt.Errorf("load control public key: %w", err)
	}
	if releasePublic.Equal(desiredPublic) || releasePublic.Equal(controlPublic) || desiredPublic.Equal(controlPublic) {
		return errors.New("serving trust keys are not distinct")
	}
	if err := tlsutil.ValidatePair(config.TLSCert, config.TLSKey); err != nil {
		return fmt.Errorf("validate TLS identity: %w", err)
	}
	if _, _, err := release.Current(config.ReleaseRoot, releasePublic); err != nil {
		return fmt.Errorf("verify current release: %w", err)
	}
	bootstrap, err := readRegular(config.BootstrapScript, 1<<20)
	if err != nil || len(bootstrap) == 0 {
		return errors.New("read bootstrap script")
	}
	enrollments, err := enrollment.NewStore(config.EnrollmentState)
	if err != nil {
		return err
	}
	statuses, err := serving.NewStatusStore(config.StatusDir)
	if err != nil {
		return err
	}
	logs, err := serving.NewLogStore(config.LogDir)
	if err != nil {
		return err
	}
	desiredStates, err := serving.NewDesiredStore(config.DesiredStateDir, desiredPublic)
	if err != nil {
		return err
	}
	audit, err := serving.NewFileAuditLog(config.AuditLog)
	if err != nil {
		return err
	}
	server, err := serving.New(serving.Config{
		Enrollments: enrollments, Statuses: statuses, Logs: logs, ReleaseRoot: config.ReleaseRoot,
		ReleasePublicKey: releasePublic, DesiredPublicKey: desiredPublic, DesiredStates: desiredStates,
		ControlPublicKey: controlPublic, Bootstrap: bootstrap, Audit: audit,
		MaxClockSkew: time.Duration(config.MaxClockSkewSeconds) * time.Second,
	})
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
	if err != nil {
		return fmt.Errorf("load TLS identity: %w", err)
	}
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	})
	httpServer := server.HTTPServer(config.Listen)
	shutdownDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = httpServer.Shutdown(shutdownContext)
			cancel()
		case <-shutdownDone:
		}
	}()
	err = httpServer.Serve(tlsListener)
	close(shutdownDone)
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return err
}

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("unsafe serving input file")
	}
	return os.ReadFile(path)
}

func securePrivateReadMode(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	mode := info.Mode().Perm()
	return mode == 0o600 && int(stat.Uid) == os.Geteuid() || mode == 0o640 && stat.Uid == 0
}

func requireRootControlledOrOwner(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("serving trust/bootstrap input is not a protected regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 && int(stat.Uid) != os.Geteuid() {
		return errors.New("serving trust/bootstrap input has an unsafe owner")
	}
	return nil
}
