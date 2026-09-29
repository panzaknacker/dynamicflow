// package tlsutil manages the serving node's transport-only TLS identity.
// TLS keys are deliberately separate from release/desired-state signing keys.
package tlsutil

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

var ErrUnsafeTLSPath = errors.New("unsafe TLS identity path")

// GenerateSelfSigned creates an Ed25519 self-signed transport certificate.
// existing files are never replaced. hardened clients pin the returned cert.
func GenerateSelfSigned(certPath, keyPath string, names []string, now time.Time) (string, error) {
	if !filepath.IsAbs(certPath) || !filepath.IsAbs(keyPath) || certPath == keyPath {
		return "", ErrUnsafeTLSPath
	}
	if len(names) == 0 {
		return "", errors.New("TLS identity needs at least one DNS name or IP")
	}
	dnsNames := []string{}
	ipAddresses := []net.IP{}
	seen := map[string]bool{}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, "/\\\x00\r\n") {
			return "", fmt.Errorf("invalid TLS name %q", name)
		}
		if ip := net.ParseIP(name); ip != nil {
			canonical := ip.String()
			if !seen["ip:"+canonical] {
				ipAddresses = append(ipAddresses, ip)
				seen["ip:"+canonical] = true
			}
			continue
		}
		name = strings.ToLower(name)
		if len(name) > 253 || strings.HasPrefix(name, "-") || strings.HasSuffix(name, ".") {
			return "", fmt.Errorf("invalid TLS DNS name %q", name)
		}
		if !seen["dns:"+name] {
			dnsNames = append(dnsNames, name)
			seen["dns:"+name] = true
		}
	}
	sort.Strings(dnsNames)
	sort.Slice(ipAddresses, func(i, j int) bool { return bytes.Compare(ipAddresses[i], ipAddresses[j]) < 0 })
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 159)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", err
	}
	commonName := names[0]
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.UTC().Add(-5 * time.Minute), NotAfter: now.UTC().AddDate(1, 1, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0,
		DNSNames: dnsNames, IPAddresses: ipAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return "", err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	if err := writeExclusive(keyPath, keyPEM, 0o600); err != nil {
		return "", err
	}
	if err := writeExclusive(certPath, certPEM, 0o644); err != nil {
		_ = os.Remove(keyPath)
		return "", err
	}
	return Fingerprint(certPath)
}

func Fingerprint(certPath string) (string, error) {
	data, err := readRegular(certPath, false)
	if err != nil {
		return "", err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("invalid TLS certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(certificate.Raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:]), nil
}

// ValidatePair checks modes, symlinks and the public/private key relationship.
func ValidatePair(certPath, keyPath string) error {
	certData, err := readRegular(certPath, false)
	if err != nil {
		return err
	}
	keyData, err := readRegular(keyPath, true)
	if err != nil {
		return err
	}
	certBlock, certRest := pem.Decode(certData)
	keyBlock, keyRest := pem.Decode(keyData)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(certRest)) != 0 ||
		keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(keyRest)) != 0 {
		return errors.New("invalid TLS PEM")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || !privateKey.Public().(ed25519.PublicKey).Equal(certificate.PublicKey) {
		return errors.New("TLS certificate/private key mismatch")
	}
	return nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafeTLSPath
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	committed = true
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func readRegular(path string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnsafeTLSPath
	}
	if private {
		mode := info.Mode().Perm()
		stat, ok := info.Sys().(*syscall.Stat_t)
		ownerOnly := mode == 0o600 && ok && int(stat.Uid) == os.Geteuid()
		rootGroupRead := mode == 0o640 && ok && stat.Uid == 0
		if !ownerOnly && !rootGroupRead {
			return nil, ErrUnsafeTLSPath
		}
	}
	return os.ReadFile(path)
}
