//go:build linux

package controlruntime

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	localPasswdPath     = "/etc/passwd"
	maxLocalPasswdBytes = 2 << 20
)

func defaultSessionDependencies() SessionDependencies {
	return SessionDependencies{
		LookupEnvironment:  os.LookupEnv,
		CurrentIdentity:    currentLocalSessionIdentity,
		ReadActiveEnvelope: readRootOwnedActiveEnvelope,
		Now:                time.Now,
	}
}

func currentLocalSessionIdentity() (SessionIdentity, error) {
	uid, effectiveUID := os.Getuid(), os.Geteuid()
	if uid <= 0 || effectiveUID <= 0 || uid != effectiveUID {
		return SessionIdentity{}, ErrSessionDenied
	}
	passwd, err := readProtectedFile("/", localPasswdPath, 0, 0, maxLocalPasswdBytes)
	if err != nil {
		return SessionIdentity{}, ErrSessionDenied
	}
	username, err := managementUsernameForUID(passwd, uid)
	if err != nil {
		return SessionIdentity{}, ErrSessionDenied
	}
	return SessionIdentity{Username: username, UID: uid, EffectiveUID: effectiveUID}, nil
}

func managementUsernameForUID(passwd []byte, uid int) (string, error) {
	if uid <= 0 || len(passwd) == 0 || len(passwd) > maxLocalPasswdBytes {
		return "", ErrSessionDenied
	}
	matchingName, matchingUID := 0, 0
	for _, line := range strings.Split(string(passwd), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			return "", ErrSessionDenied
		}
		accountUID, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil || strconv.FormatUint(accountUID, 10) != fields[2] {
			// UID aliases such as 01001 still identify numeric UID 1001 on
			// Linux. Reject a noncanonical account database before counting
			// identities, so no alternate spelling conceals a shared UID.
			return "", ErrSessionDenied
		}
		if fields[0] == ManagementUser {
			matchingName++
			if accountUID != uint64(uid) {
				return "", ErrSessionDenied
			}
		}
		if accountUID == uint64(uid) {
			matchingUID++
			if fields[0] != ManagementUser {
				return "", ErrSessionDenied
			}
		}
	}
	if matchingName != 1 || matchingUID != 1 {
		return "", ErrSessionDenied
	}
	return ManagementUser, nil
}

func readRootOwnedActiveEnvelope(stateRoot string) ([]byte, error) {
	if stateRoot != DefaultStateRoot || !safeAbsolutePath(stateRoot) {
		return nil, ErrUnsafeHost
	}
	return readActiveEnvelopeAt("/", stateRoot, 0, 0)
}

func readActiveEnvelopeAt(anchor, stateRoot string, ownerUID, ownerGID uint32) ([]byte, error) {
	if !safeTrustAnchor(anchor) || !safeAbsolutePath(stateRoot) ||
		!pathInside(anchor, stateRoot) {
		return nil, ErrUnsafeHost
	}
	activePath := filepath.Join(stateRoot, ActiveBundleName)
	if filepath.Clean(activePath) != activePath || !pathInside(stateRoot, activePath) {
		return nil, ErrUnsafeHost
	}
	active, err := openTrustedDirectory(anchor, activePath, false, ownerUID, ownerGID)
	if err != nil {
		return nil, ErrUnsafeHost
	}
	defer active.Close()
	data, err := readManagedFileAt(
		active,
		"envelope.json",
		0o444,
		ownerUID,
		ownerGID,
		MaxEnvelopeBytes,
	)
	if err != nil {
		return nil, ErrUnsafeHost
	}
	return data, nil
}
