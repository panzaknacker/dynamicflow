// Package signing implements the small, domain-separated Ed25519 trust root used
// by Dynamicflow manifests and desired-state documents.
package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	privatePEMType  = "PRIVATE KEY"
	publicPEMType   = "PUBLIC KEY"
	algorithm       = "Ed25519"
	signatureV1     = 1
	maxKeyFileBytes = 16 << 10
)

var (
	ErrInvalidKey       = errors.New("invalid Ed25519 key")
	ErrInvalidSignature = errors.New("invalid Ed25519 signature")
	ErrUnsafeKeyFile    = errors.New("unsafe key file")
)

// Signature contains no secret material. KeyID is the SHA-256 digest of the
// PKIX-encoded public key. Encoding Signature as JSON represents Value as
// base64, so the binary signature is never mistaken for display text.
type Signature struct {
	Version   int    `json:"version"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     []byte `json:"value"`
}

// Generate returns a fresh Ed25519 key pair.
func Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	return publicKey, privateKey, nil
}

// KeyID returns the full SHA-256 digest of the PKIX-encoded public key.
func KeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", ErrInvalidKey
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:]), nil
}

func MarshalPrivatePEM(privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKey
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8 private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: privatePEMType, Bytes: der}), nil
}

func MarshalPublicPEM(publicKey ed25519.PublicKey) ([]byte, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidKey
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal PKIX public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: publicPEMType, Bytes: der}), nil
}

func ParsePrivatePEM(data []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != privatePEMType || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalidKey
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", ErrInvalidKey)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKey
	}
	return privateKey, nil
}

func ParsePublicPEM(data []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != publicPEMType || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalidKey
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", ErrInvalidKey)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidKey
	}
	return publicKey, nil
}

// GenerateFiles creates a new unencrypted PKCS#8 private key with mode 0600
// and its public PKIX PEM file with mode 0644. Existing paths are never
// overwritten.
func GenerateFiles(privatePath, publicPath string) (ed25519.PublicKey, error) {
	publicKey, privateKey, err := Generate()
	if err != nil {
		return nil, err
	}
	privatePEM, err := MarshalPrivatePEM(privateKey)
	if err != nil {
		return nil, err
	}
	publicPEM, err := MarshalPublicPEM(publicKey)
	if err != nil {
		return nil, err
	}
	if err := writeNewFile(privatePath, privatePEM, 0o600); err != nil {
		return nil, fmt.Errorf("write private key: %w", err)
	}
	if err := writeNewFile(publicPath, publicPEM, 0o644); err != nil {
		_ = os.Remove(privatePath)
		return nil, fmt.Errorf("write public key: %w", err)
	}
	return publicKey, nil
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%w: key path must be absolute", ErrUnsafeKeyFile)
	}
	directory := filepath.Dir(path)
	if err := ensureSecureKeyDirectory(directory); err != nil {
		return err
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
	return syncDirectory(directory)
}

func LoadPrivateFile(path string) (ed25519.PrivateKey, error) {
	data, err := readRegularFile(path, 0o600, true)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return ParsePrivatePEM(data)
}

func LoadPublicFile(path string) (ed25519.PublicKey, error) {
	data, err := readRegularFile(path, 0, false)
	if err != nil {
		return nil, err
	}
	return ParsePublicPEM(data)
}

func readRegularFile(path string, exactMode os.FileMode, requireExactMode bool) ([]byte, error) {
	file, err := openKeyFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > maxKeyFileBytes {
		return nil, fmt.Errorf("%w: key must be a bounded single-link regular file", ErrUnsafeKeyFile)
	}
	if requireExactMode && info.Mode().Perm() != exactMode {
		return nil, fmt.Errorf("%w: private key mode must be 0600", ErrUnsafeKeyFile)
	}
	if requireExactMode && int(stat.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("%w: private key has wrong owner", ErrUnsafeKeyFile)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%w: key is writable by another user", ErrUnsafeKeyFile)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxKeyFileBytes+1))
	if err != nil {
		clear(data)
		return nil, err
	}
	if len(data) > maxKeyFileBytes {
		clear(data)
		return nil, fmt.Errorf("%w: key exceeds its size bound", ErrUnsafeKeyFile)
	}
	return data, nil
}

// openKeyFile pins each directory descriptor before opening its child. No
// parent or final symlink is followed, and a substituted FIFO cannot block
// before the caller verifies the descriptor's type, owner and link count.
func openKeyFile(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || absolute == string(filepath.Separator) || strings.IndexByte(path, 0) >= 0 {
		return nil, ErrUnsafeKeyFile
	}
	parts := strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator))
	current, err := syscall.Open(string(filepath.Separator), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = syscall.Close(current) }()
	for _, part := range parts[:len(parts)-1] {
		next, err := syscall.Openat(current, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if err != nil {
			if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
				return nil, ErrUnsafeKeyFile
			}
			return nil, err
		}
		_ = syscall.Close(current)
		current = next
	}
	fd, err := syscall.Openat(current, parts[len(parts)-1], syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrUnsafeKeyFile
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), absolute), nil
}

func ensureSecureKeyDirectory(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return fmt.Errorf("%w: unsafe key directory", ErrUnsafeKeyFile)
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if mkdirErr := os.Mkdir(current, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				return mkdirErr
			}
			info, err = os.Lstat(current)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: key path contains a symlink or non-directory", ErrUnsafeKeyFile)
		}
	}
	info, err := os.Lstat(clean)
	if err != nil || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: key directory is group/world writable", ErrUnsafeKeyFile)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: key directory has wrong owner", ErrUnsafeKeyFile)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// CanonicalJSON emits the deterministic JSON subset used by Dynamicflow. Map
// keys are sorted, integer spellings are normalized, and fractional/floating
// point numbers are rejected to avoid cross-runtime ambiguity.
func CanonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical JSON input: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, fmt.Errorf("decode canonical JSON input: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := writeCanonical(&output, normalized); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("canonical JSON input contains multiple values")
	}
	return err
}

func writeCanonical(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case string:
		encoded, _ := json.Marshal(typed)
		output.Write(encoded)
	case json.Number:
		text := string(typed)
		if strings.ContainsAny(text, ".eE") {
			return errors.New("canonical JSON does not permit floating-point numbers")
		}
		integer := new(big.Int)
		if _, ok := integer.SetString(text, 10); !ok {
			return fmt.Errorf("invalid canonical integer %q", text)
		}
		output.WriteString(integer.String())
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeCanonical(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			encoded, _ := json.Marshal(key)
			output.Write(encoded)
			output.WriteByte(':')
			if err := writeCanonical(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
	return nil
}

func signingMessage(domain string, value any) ([]byte, error) {
	if domain == "" || strings.ContainsRune(domain, '\x00') {
		return nil, errors.New("signature domain must be non-empty and contain no NUL")
	}
	canonical, err := CanonicalJSON(value)
	if err != nil {
		return nil, err
	}
	prefix := []byte("dynamicflow-signature-v1\x00" + domain + "\x00")
	return append(prefix, canonical...), nil
}

// SignCanonical signs a canonical, domain-separated representation of value.
func SignCanonical(privateKey ed25519.PrivateKey, domain string, value any) (Signature, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Signature{}, ErrInvalidKey
	}
	message, err := signingMessage(domain, value)
	if err != nil {
		return Signature{}, err
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return Signature{}, ErrInvalidKey
	}
	keyID, err := KeyID(publicKey)
	if err != nil {
		return Signature{}, err
	}
	return Signature{
		Version:   signatureV1,
		Algorithm: algorithm,
		KeyID:     keyID,
		Value:     ed25519.Sign(privateKey, message),
	}, nil
}

// VerifyCanonical verifies the signature, key identifier, domain and exact
// canonical value binding.
func VerifyCanonical(publicKey ed25519.PublicKey, domain string, value any, signature Signature) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidKey
	}
	if signature.Version != signatureV1 || signature.Algorithm != algorithm || len(signature.Value) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	keyID, err := KeyID(publicKey)
	if err != nil || signature.KeyID != keyID {
		return ErrInvalidSignature
	}
	message, err := signingMessage(domain, value)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, message, signature.Value) {
		return ErrInvalidSignature
	}
	return nil
}
