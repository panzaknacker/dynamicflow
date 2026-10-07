package operatortrust

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/signing"
)

// Load verifies the committed bundle against every existing public/private
// pair. It never creates, repairs, rotates or rewrites trust material.
func Load(store *localstate.Store) (Bundle, error) {
	if store == nil {
		return Bundle{}, errors.New("operator trust store is required")
	}
	var bundle Bundle
	if err := store.ReadJSON("keys/signing/trust.json", &bundle); err != nil {
		return Bundle{}, fmt.Errorf("read committed trust bundle: %w", err)
	}
	if err := Validate(bundle); err != nil {
		return Bundle{}, err
	}
	expected := map[string]string{
		"system-root": bundle.SystemRoot, "release": bundle.Release, "desired-state": bundle.DesiredState,
		"serving-admin": bundle.ServingAdmin, "control-policy": bundle.ControlPolicy,
	}
	for _, item := range roles {
		keyID, err := loadRoleKeyID(store, item)
		if err != nil {
			return Bundle{}, err
		}
		if keyID != expected[item.name] {
			return Bundle{}, fmt.Errorf("%s key does not match the committed trust bundle", item.name)
		}
	}
	return bundle, nil
}

func loadRoleKeyID(store *localstate.Store, item role) (string, error) {
	privatePath, err := store.Path(filepath.Join("keys", "signing", item.base+".private.pem"))
	if err != nil {
		return "", err
	}
	publicPath, err := store.Path(filepath.Join("keys", "signing", item.base+".public.pem"))
	if err != nil {
		return "", err
	}
	private, err := signing.LoadPrivateFile(privatePath)
	if err != nil {
		return "", fmt.Errorf("load %s private key: %w", item.name, err)
	}
	defer clear(private)
	public, err := signing.LoadPublicFile(publicPath)
	if err != nil || !private.Public().(ed25519.PublicKey).Equal(public) {
		return "", fmt.Errorf("%s trust pair does not match", item.name)
	}
	return signing.KeyID(public)
}
