// Package operatortrust manages per-system, role-separated offline signing
// roots. It exposes identifiers only; private bytes and paths never leave it.
package operatortrust

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"dynamicflow/internal/controlpolicy"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/signing"
)

const SchemaVersion = 1

type Bundle struct {
	SchemaVersion int    `json:"schema_version"`
	SystemRoot    string `json:"system_root_key_id"`
	Release       string `json:"release_key_id"`
	DesiredState  string `json:"desired_state_key_id"`
	ServingAdmin  string `json:"serving_admin_key_id"`
	ControlPolicy string `json:"control_policy_key_id"`
}

type role struct {
	name string
	base string
}

var roles = []role{
	{name: "system-root", base: "system-root"},
	{name: "release", base: "release"},
	{name: "desired-state", base: "desired-state"},
	{name: "serving-admin", base: "serving-admin"},
	{name: "control-policy", base: "control-policy"},
}

func Ensure(store *localstate.Store) (Bundle, error) {
	if store == nil {
		return Bundle{}, errors.New("operator trust store is required")
	}
	// Existing trust is a read-only operation, including when its obsolete
	// initialization lock file is absent. Recheck after locking only for the
	// concurrent initial-creation case below.
	var committed Bundle
	if err := store.ReadJSON("keys/signing/trust.json", &committed); err == nil {
		return Load(store)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Bundle{}, fmt.Errorf("read committed operator trust: %w", err)
	}
	var result Bundle
	err := store.WithLock("keys/signing/.trust.lock", func() error {
		var committed Bundle
		if err := store.ReadJSON("keys/signing/trust.json", &committed); err == nil {
			// Once committed, trust is immutable through Ensure. In particular,
			// losing both halves of a pair must not silently create a new root.
			var loadErr error
			result, loadErr = Load(store)
			return loadErr
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read committed operator trust: %w", err)
		}
		directory, err := store.EnsureDir("keys/signing")
		if err != nil {
			return err
		}
		ids := make(map[string]string, len(roles))
		for _, item := range roles {
			privatePath := filepath.Join(directory, item.base+".private.pem")
			publicPath := filepath.Join(directory, item.base+".public.pem")
			privateExists := exists(privatePath)
			publicExists := exists(publicPath)
			if privateExists != publicExists {
				return fmt.Errorf("%s trust root is incomplete", item.name)
			}
			if !privateExists {
				if _, err := signing.GenerateFiles(privatePath, publicPath); err != nil {
					return fmt.Errorf("generate %s trust root: %w", item.name, err)
				}
			}
			ids[item.name], err = loadRoleKeyID(store, item)
			if err != nil {
				return err
			}
		}
		values := make([]string, 0, len(ids))
		for _, id := range ids {
			values = append(values, id)
		}
		sort.Strings(values)
		for index := 1; index < len(values); index++ {
			if values[index] == values[index-1] {
				return errors.New("operator trust roles share one Ed25519 root")
			}
		}
		result = Bundle{
			SchemaVersion: SchemaVersion,
			SystemRoot:    ids["system-root"],
			Release:       ids["release"], DesiredState: ids["desired-state"],
			ServingAdmin: ids["serving-admin"], ControlPolicy: ids["control-policy"],
		}
		return store.WriteJSON("keys/signing/trust.json", result)
	})
	return result, err
}

func Validate(bundle Bundle) error {
	if bundle.SchemaVersion != SchemaVersion || bundle.SystemRoot == "" || bundle.Release == "" || bundle.DesiredState == "" ||
		bundle.ServingAdmin == "" || bundle.ControlPolicy == "" {
		return errors.New("invalid operator trust bundle")
	}
	ids := []string{bundle.SystemRoot, bundle.Release, bundle.DesiredState, bundle.ServingAdmin, bundle.ControlPolicy}
	sort.Strings(ids)
	for index := 1; index < len(ids); index++ {
		if ids[index] == ids[index-1] {
			return errors.New("operator trust roles are not separated")
		}
	}
	return nil
}

// SignControlPolicy signs only the fixed control-policy domain with the
// per-system ControlPolicy root. Private key bytes remain inside this package
// and are cleared before return.
func SignControlPolicy(store *localstate.Store, policy controlpolicy.Policy) (controlpolicy.SignedPolicy, error) {
	if store == nil {
		return controlpolicy.SignedPolicy{}, errors.New("operator trust store is required")
	}
	privatePath, err := store.Path("keys/signing/control-policy.private.pem")
	if err != nil {
		return controlpolicy.SignedPolicy{}, err
	}
	publicPath, err := store.Path("keys/signing/control-policy.public.pem")
	if err != nil {
		return controlpolicy.SignedPolicy{}, err
	}
	private, err := signing.LoadPrivateFile(privatePath)
	if err != nil {
		return controlpolicy.SignedPolicy{}, fmt.Errorf("load Control-policy signer: %w", err)
	}
	defer clear(private)
	public, err := signing.LoadPublicFile(publicPath)
	if err != nil || !private.Public().(ed25519.PublicKey).Equal(public) {
		return controlpolicy.SignedPolicy{}, errors.New("Control-policy signing pair does not match")
	}
	return controlpolicy.Sign(policy, private)
}

// ControlPolicyPublic returns a detached public PEM and key ID suitable for
// the pinned first-Control installation envelope. It never creates trust state
// or exposes the private key path.
func ControlPolicyPublic(store *localstate.Store) ([]byte, string, error) {
	if store == nil {
		return nil, "", errors.New("operator trust store is required")
	}
	publicPath, err := store.Path("keys/signing/control-policy.public.pem")
	if err != nil {
		return nil, "", err
	}
	public, err := signing.LoadPublicFile(publicPath)
	if err != nil {
		return nil, "", fmt.Errorf("load Control-policy public key: %w", err)
	}
	keyID, err := signing.KeyID(public)
	if err != nil {
		return nil, "", err
	}
	pemBytes, err := signing.MarshalPublicPEM(public)
	if err != nil {
		return nil, "", err
	}
	return append([]byte(nil), pemBytes...), keyID, nil
}

func exists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
