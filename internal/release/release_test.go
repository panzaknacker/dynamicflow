package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"

	"dynamicflow/internal/signing"
)

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func buildFixture(t *testing.T, generation uint64, contents string) (Manifest, map[string]string) {
	t.Helper()
	return buildExplicitFixture(t, generation, fmt.Sprintf("v1.2.%d", generation), "any", "ssh.tar.gz", contents)
}

func buildExplicitFixture(t *testing.T, generation uint64, version, target, artifactName, contents string) (Manifest, map[string]string) {
	t.Helper()
	directory := t.TempDir()
	artifact := filepath.Join(directory, artifactName)
	if err := os.WriteFile(artifact, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, err := BuildFromArtifacts(generation, []ArtifactInput{{
		Component: "ssh", Version: version, Target: target, ArtifactName: artifactName, SourcePath: artifact,
	}}, []Profile{{Name: "ssh", Components: []string{"ssh"}}}, []Revocation{{
		Component: "ssh", Version: "v0.1.5", Reason: "embedded obsolete operator key",
	}})
	if err != nil {
		t.Fatal(err)
	}
	return manifest, map[string]string{manifest.Components[0].Artifact: artifact}
}

func materializeVersionArtifact(t *testing.T, root string, manifest Manifest, paths map[string]string) string {
	t.Helper()
	component := manifest.Components[0]
	destination := filepath.Join(root, filepath.FromSlash(component.Artifact))
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(paths[component.Artifact])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return destination
}

func snapshotReleaseTree(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		details, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("release snapshot metadata is unavailable")
		}
		value := fmt.Sprintf("mode=%v;size=%d;uid=%d;gid=%d;nlink=%d", info.Mode(), info.Size(), details.Uid, details.Gid, details.Nlink)
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			value += ";target=" + target
		case info.Mode().IsRegular():
			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += fmt.Sprintf(";sha256=%x", sha256.Sum256(contents))
		}
		snapshot[filepath.ToSlash(relative)] = value
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestVersionHistoryIsImmutable(t *testing.T) {
	previous, _ := buildExplicitFixture(t, 1, "v4.0.0", "any", "ssh.tar.gz", "same bytes")
	same, _ := buildExplicitFixture(t, 2, "v4.0.0", "any", "ssh.tar.gz", "same bytes")
	if err := CheckVersionHistory(previous, same); err != nil {
		t.Fatalf("identical version binding was rejected: %v", err)
	}

	for _, test := range []struct {
		name         string
		artifactName string
		contents     string
	}{
		{name: "digest-and-size", artifactName: "ssh.tar.gz", contents: "different bytes"},
		{name: "digest-same-size", artifactName: "ssh.tar.gz", contents: "same byteS"},
		{name: "artifact-name", artifactName: "renamed.tar.gz", contents: "same bytes"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate, _ := buildExplicitFixture(t, 2, "v4.0.0", "any", test.artifactName, test.contents)
			if err := CheckVersionHistory(previous, candidate); !errors.Is(err, ErrVersionConflict) {
				t.Fatalf("error=%v, want ErrVersionConflict", err)
			}
		})
	}
}

func TestGenerationHistoryRejectsRollbackAndReuse(t *testing.T) {
	previous, _ := buildExplicitFixture(t, 10, "v4.1.0", "any", "ssh.tar.gz", "previous")
	lower, _ := buildExplicitFixture(t, 9, "v4.2.0", "any", "ssh.tar.gz", "lower")
	if err := CheckGenerationHistory(previous, lower); !errors.Is(err, ErrReleaseRollback) {
		t.Fatalf("lower generation error=%v, want ErrReleaseRollback", err)
	}
	equalDifferent, _ := buildExplicitFixture(t, 10, "v4.2.0", "any", "ssh.tar.gz", "different")
	if err := CheckGenerationHistory(previous, equalDifferent); !errors.Is(err, ErrReleaseRollback) {
		t.Fatalf("reused generation error=%v, want ErrReleaseRollback", err)
	}
	identical, _ := buildExplicitFixture(t, 10, "v4.1.0", "any", "ssh.tar.gz", "previous")
	if err := CheckGenerationHistory(previous, identical); err != nil {
		t.Fatalf("identical fixed-generation rebuild: %v", err)
	}
	higher, _ := buildExplicitFixture(t, 11, "v4.2.0", "any", "ssh.tar.gz", "higher")
	if err := CheckGenerationHistory(previous, higher); err != nil {
		t.Fatalf("higher generation: %v", err)
	}
}

func TestImmutableVersionRootMissingExactAndCollision(t *testing.T) {
	manifest, paths := buildExplicitFixture(t, 1, "v4.1.0", "any", "ssh.tar.gz", "trusted release bytes")

	t.Run("missing root", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "missing")
		if err := CheckImmutableVersionRoot(root, manifest); err != nil {
			t.Fatalf("missing root: %v", err)
		}
	})

	t.Run("missing final", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "versions")
		parent := filepath.Dir(filepath.Join(root, filepath.FromSlash(manifest.Components[0].Artifact)))
		if err := os.MkdirAll(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := CheckImmutableVersionRoot(root, manifest); err != nil {
			t.Fatalf("missing final: %v", err)
		}
	})

	t.Run("exact existing bytes", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "versions")
		materializeVersionArtifact(t, root, manifest, paths)
		if err := CheckImmutableVersionRoot(root, manifest); err != nil {
			t.Fatalf("exact binding: %v", err)
		}
	})

	t.Run("different existing bytes", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "versions")
		artifact := materializeVersionArtifact(t, root, manifest, paths)
		if err := os.WriteFile(artifact, []byte("other release bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := CheckImmutableVersionRoot(root, manifest); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("error=%v, want ErrVersionConflict", err)
		}
	})

	t.Run("different existing artifact name", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "versions")
		expected := filepath.Join(root, filepath.FromSlash(manifest.Components[0].Artifact))
		if err := os.MkdirAll(filepath.Dir(expected), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(filepath.Dir(expected), "renamed.tar.gz"), []byte("trusted release bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := CheckImmutableVersionRoot(root, manifest); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("error=%v, want ErrVersionConflict", err)
		}
	})

	t.Run("size mismatch precedes content scan", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "versions")
		artifact := materializeVersionArtifact(t, root, manifest, paths)
		mismatched := append([]byte("different-size:"), privateKeyMarker("")...)
		if err := os.WriteFile(artifact, mismatched, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := CheckImmutableVersionRoot(root, manifest); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("error=%v, want ErrVersionConflict", err)
		}
	})
}

func TestImmutableVersionRootRejectsUnsafeEntries(t *testing.T) {
	manifest, paths := buildExplicitFixture(t, 1, "v4.2.0", "any", "ssh.tar.gz", "trusted release bytes")
	logical := filepath.FromSlash(manifest.Components[0].Artifact)

	for _, test := range []struct {
		name  string
		setup func(*testing.T, string, string)
	}{
		{
			name: "final symlink",
			setup: func(t *testing.T, root, artifact string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(artifact), 0o700); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(outside, []byte("trusted release bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, artifact); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hardlink",
			setup: func(t *testing.T, root, artifact string) {
				t.Helper()
				materializeVersionArtifact(t, root, manifest, paths)
				if err := os.Link(artifact, artifact+".held"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory",
			setup: func(t *testing.T, root, artifact string) {
				t.Helper()
				if err := os.MkdirAll(artifact, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "fifo",
			setup: func(t *testing.T, root, artifact string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(artifact), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(artifact, 0o600); err != nil {
					t.Skipf("mkfifo unavailable: %v", err)
				}
			},
		},
		{
			name: "group writable artifact",
			setup: func(t *testing.T, root, artifact string) {
				t.Helper()
				materializeVersionArtifact(t, root, manifest, paths)
				if err := os.Chmod(artifact, 0o660); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "group writable directory",
			setup: func(t *testing.T, root, artifact string) {
				t.Helper()
				materializeVersionArtifact(t, root, manifest, paths)
				if err := os.Chmod(filepath.Dir(artifact), 0o770); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "versions")
			artifact := filepath.Join(root, logical)
			test.setup(t, root, artifact)
			if err := CheckImmutableVersionRoot(root, manifest); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("error=%v, want ErrUnsafePath", err)
			}
		})
	}

	t.Run("symlink ancestor with missing final", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "versions")
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(root, "ssh")); err != nil {
			t.Fatal(err)
		}
		if err := CheckImmutableVersionRoot(root, manifest); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("error=%v, want ErrUnsafePath", err)
		}
	})

	t.Run("symlink root", func(t *testing.T) {
		realRoot := filepath.Join(t.TempDir(), "real")
		materializeVersionArtifact(t, realRoot, manifest, paths)
		root := filepath.Join(t.TempDir(), "linked")
		if err := os.Symlink(realRoot, root); err != nil {
			t.Fatal(err)
		}
		if err := CheckImmutableVersionRoot(root, manifest); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("error=%v, want ErrUnsafePath", err)
		}
	})
}

func TestManifestRequiresOneVersionAcrossComponentTargets(t *testing.T) {
	directory := t.TempDir()
	amd64 := filepath.Join(directory, "amd64")
	arm64 := filepath.Join(directory, "arm64")
	if err := os.WriteFile(amd64, []byte("amd64"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(arm64, []byte("arm64"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := BuildFromArtifacts(1, []ArtifactInput{
		{Component: "flow", Version: "v1.0.0", Target: "linux-amd64", ArtifactName: "flow", SourcePath: amd64},
		{Component: "flow", Version: "v1.0.1", Target: "linux-arm64", ArtifactName: "flow", SourcePath: arm64},
	}, []Profile{{Name: "flow", Components: []string{"flow"}}}, nil)
	if !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("error=%v, want ErrInvalidManifest", err)
	}
}

func TestManifestRejectsAnyAndExactTargetAmbiguity(t *testing.T) {
	directory := t.TempDir()
	generic := filepath.Join(directory, "generic")
	amd64 := filepath.Join(directory, "amd64")
	if err := os.WriteFile(generic, []byte("generic"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(amd64, []byte("amd64"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := BuildFromArtifacts(1, []ArtifactInput{
		{Component: "flow", Version: "v1.0.0", Target: "any", ArtifactName: "flow", SourcePath: generic},
		{Component: "flow", Version: "v1.0.0", Target: "linux-amd64", ArtifactName: "flow", SourcePath: amd64},
	}, []Profile{{Name: "flow", Components: []string{"flow"}}}, nil)
	if !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("error=%v, want ErrInvalidManifest", err)
	}
}

func TestPublishRejectsCollisionWithNonCurrentRetainedSet(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	first, firstPaths := buildExplicitFixture(t, 1, "v5.0.0", "any", "ssh.tar.gz", "version-five original")
	firstSigned, err := SignManifest(first, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, firstSigned, firstPaths, publicKey); err != nil {
		t.Fatal(err)
	}
	second, secondPaths := buildExplicitFixture(t, 2, "v6.0.0", "any", "ssh.tar.gz", "version-six")
	secondSigned, err := SignManifest(second, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, secondSigned, secondPaths, publicKey); err != nil {
		t.Fatal(err)
	}
	currentBefore, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}

	collision, collisionPaths := buildExplicitFixture(t, 3, "v5.0.0", "any", "ssh.tar.gz", "version-five changed")
	collisionSigned, err := SignManifest(collision, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, collisionSigned, collisionPaths, publicKey); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("error=%v, want ErrVersionConflict", err)
	}
	currentAfter, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if currentAfter != currentBefore {
		t.Fatalf("collision changed current: %q != %q", currentAfter, currentBefore)
	}
	collisionSet := filepath.Join(root, "sets", strings.TrimPrefix(collision.SetID, "sha256:"))
	if _, err := os.Lstat(collisionSet); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("collision set was staged: %v", err)
	}
}

func TestPublishAllowsIdenticalVersionBindingAcrossGenerations(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	for _, generation := range []uint64{1, 2} {
		manifest, paths := buildExplicitFixture(t, generation, "v5.1.0", "any", "ssh.tar.gz", "identical bytes")
		signed, err := SignManifest(manifest, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := Publish(root, signed, paths, publicKey); err != nil {
			t.Fatalf("generation %d: %v", generation, err)
		}
	}
	current, _, err := Current(root, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if current.Manifest.Generation != 2 {
		t.Fatalf("current generation=%d, want 2", current.Manifest.Generation)
	}
}

func TestPublishRejectsArtifactRenameForRetainedVersion(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	first, firstPaths := buildExplicitFixture(t, 1, "v5.2.0", "any", "ssh.tar.gz", "identical bytes")
	firstSigned, err := SignManifest(first, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, firstSigned, firstPaths, publicKey); err != nil {
		t.Fatal(err)
	}
	renamed, renamedPaths := buildExplicitFixture(t, 2, "v5.2.0", "any", "renamed.tar.gz", "identical bytes")
	renamedSigned, err := SignManifest(renamed, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, renamedSigned, renamedPaths, publicKey); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("error=%v, want ErrVersionConflict", err)
	}
}

func TestRetainedScannerRejectsPreexistingVersionConflict(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	otherRoot := filepath.Join(t.TempDir(), "other-release-root")
	first, firstPaths := buildExplicitFixture(t, 1, "v5.3.0", "any", "ssh.tar.gz", "first bytes")
	firstSigned, err := SignManifest(first, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, firstSigned, firstPaths, publicKey); err != nil {
		t.Fatal(err)
	}
	conflicting, conflictingPaths := buildExplicitFixture(t, 2, "v5.3.0", "any", "ssh.tar.gz", "conflicting bytes")
	conflictingSigned, err := SignManifest(conflicting, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(otherRoot, conflictingSigned, conflictingPaths, publicKey); err != nil {
		t.Fatal(err)
	}
	conflictingName := strings.TrimPrefix(conflicting.SetID, "sha256:")
	if err := os.Rename(filepath.Join(otherRoot, "sets", conflictingName), filepath.Join(root, "sets", conflictingName)); err != nil {
		t.Fatal(err)
	}

	candidate, candidatePaths := buildExplicitFixture(t, 3, "v5.4.0", "any", "ssh.tar.gz", "independent bytes")
	candidateSigned, err := SignManifest(candidate, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, candidateSigned, candidatePaths, publicKey); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("error=%v, want retained-history ErrVersionConflict", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "history", conflictingName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed conflicting scan partially backfilled history: %v", err)
	}
}

func TestManifestHistoryPreservesVersionsAndHighWaterAfterArtifactPruning(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	first, firstPaths := buildExplicitFixture(t, 1, "v5.5.0", "any", "ssh.tar.gz", "version-five original")
	firstSigned, err := SignManifest(first, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, firstSigned, firstPaths, publicKey); err != nil {
		t.Fatal(err)
	}
	second, secondPaths := buildExplicitFixture(t, 2, "v6.5.0", "any", "ssh.tar.gz", "version-six")
	secondSigned, err := SignManifest(second, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, secondSigned, secondPaths, publicKey); err != nil {
		t.Fatal(err)
	}
	firstName := strings.TrimPrefix(first.SetID, "sha256:")
	secondName := strings.TrimPrefix(second.SetID, "sha256:")
	for _, name := range []string{firstName, secondName} {
		manifestPath := filepath.Join(root, "history", name, "signed-manifest.json")
		info, err := os.Lstat(manifestPath)
		if err != nil {
			t.Fatalf("history manifest %s: %v", name, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 {
			t.Fatalf("history manifest %s: mode=%v", name, info.Mode())
		}
	}
	if err := os.RemoveAll(filepath.Join(root, "sets", firstName)); err != nil {
		t.Fatal(err)
	}
	collision, collisionPaths := buildExplicitFixture(t, 3, "v5.5.0", "any", "ssh.tar.gz", "version-five rebound")
	collisionSigned, err := SignManifest(collision, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, collisionSigned, collisionPaths, publicKey); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("pruned version collision error=%v, want ErrVersionConflict", err)
	}

	if err := os.RemoveAll(filepath.Join(root, "sets", secondName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	lower, lowerPaths := buildExplicitFixture(t, 1, "v7.0.0", "any", "ssh.tar.gz", "otherwise independent")
	lowerSigned, err := SignManifest(lower, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, lowerSigned, lowerPaths, publicKey); !errors.Is(err, ErrReleaseRollback) {
		t.Fatalf("pruned high-water error=%v, want ErrReleaseRollback", err)
	}
}

func TestPublishRejectsUnsafeManifestHistory(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	first, paths := buildExplicitFixture(t, 1, "v5.6.0", "any", "ssh.tar.gz", "release")
	signed, err := SignManifest(first, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, signed, paths, publicKey); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "history", strings.TrimPrefix(first.SetID, "sha256:"), "signed-manifest.json")
	if err := os.Chmod(manifestPath, 0o644); err != nil {
		t.Fatal(err)
	}
	candidate, candidatePaths := buildExplicitFixture(t, 2, "v5.7.0", "any", "ssh.tar.gz", "next")
	candidateSigned, err := SignManifest(candidate, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, candidateSigned, candidatePaths, publicKey); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("error=%v, want ErrUnsafePath", err)
	}
}

func TestPublishRejectsWritableHistoryDirectoryBeforeMutation(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	if err := os.MkdirAll(filepath.Join(root, "history"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "history"), 0o777); err != nil {
		t.Fatal(err)
	}
	manifest, paths := buildExplicitFixture(t, 1, "v5.8.0", "any", "ssh.tar.gz", "release")
	signed, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, signed, paths, publicKey); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("error=%v, want ErrUnsafePath", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe history publish changed current: %v", err)
	}
}

func TestPublishPolicyAndPublishResumeCrashWindows(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	first, firstPaths := buildExplicitFixture(t, 1, "v8.0.0", "any", "ssh.tar.gz", "first")
	firstSigned, err := SignManifest(first, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, firstSigned, firstPaths, publicKey); err != nil {
		t.Fatal(err)
	}
	firstName := strings.TrimPrefix(first.SetID, "sha256:")
	if err := os.RemoveAll(filepath.Join(root, "history")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := CheckPublishPolicy(root, firstSigned, publicKey); err != nil {
		t.Fatalf("set-only policy preflight: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "history")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only preflight recreated history: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only preflight recreated current: %v", err)
	}
	for _, source := range firstPaths {
		if err := os.Remove(source); err != nil {
			t.Fatalf("remove transient source before committed-set resume: %v", err)
		}
	}
	if err := Publish(root, firstSigned, firstPaths, publicKey); err != nil {
		t.Fatalf("resume committed set without source/history/current: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "history", firstName, "signed-manifest.json")); err != nil {
		t.Fatalf("resume did not backfill history: %v", err)
	}

	if err := os.Mkdir(filepath.Join(root, "sets", ".stage-interrupted"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "history", ".stage-interrupted"), 0o700); err != nil {
		t.Fatal(err)
	}
	second, secondPaths := buildExplicitFixture(t, 2, "v8.1.0", "any", "ssh.tar.gz", "second")
	secondSigned, err := SignManifest(second, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, secondSigned, secondPaths, publicKey); err != nil {
		t.Fatalf("resume with orphan stages: %v", err)
	}
	secondName := strings.TrimPrefix(second.SetID, "sha256:")
	if err := os.Remove(filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.ToSlash(filepath.Join("sets", firstName)), filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, secondSigned, secondPaths, publicKey); err != nil {
		t.Fatalf("resume set+history with predecessor current: %v", err)
	}
	currentTarget, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || currentTarget != filepath.ToSlash(filepath.Join("sets", secondName)) {
		t.Fatalf("current was not recovered: target=%q err=%v", currentTarget, err)
	}

	if err := os.RemoveAll(filepath.Join(root, "history", firstName)); err != nil {
		t.Fatal(err)
	}
	third, thirdPaths := buildExplicitFixture(t, 3, "v8.2.0", "any", "ssh.tar.gz", "third")
	thirdSigned, err := SignManifest(third, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, thirdSigned, thirdPaths, publicKey); err != nil {
		t.Fatalf("resume partial history backfill: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "history", firstName, "signed-manifest.json")); err != nil {
		t.Fatalf("partial history was not backfilled: %v", err)
	}
}

func TestCheckPublishPolicyNeverMutatesExistingRoot(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	first, firstPaths := buildExplicitFixture(t, 1, "v9.0.0", "any", "ssh.tar.gz", "first")
	firstSigned, err := SignManifest(first, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, firstSigned, firstPaths, publicKey); err != nil {
		t.Fatal(err)
	}
	second, secondPaths := buildExplicitFixture(t, 2, "v9.1.0", "any", "ssh.tar.gz", "second")
	secondSigned, err := SignManifest(second, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, secondSigned, secondPaths, publicKey); err != nil {
		t.Fatal(err)
	}
	firstName := strings.TrimPrefix(first.SetID, "sha256:")
	if err := os.RemoveAll(filepath.Join(root, "history", firstName)); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		filepath.Join(root, "sets", ".stage-interrupted"),
		filepath.Join(root, "history", ".stage-interrupted"),
	} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "sentinel"), []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	assertUnchanged := func(name string, run func() error, want error) {
		t.Helper()
		before := snapshotReleaseTree(t, root)
		err := run()
		if want == nil && err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if want != nil && !errors.Is(err, want) {
			t.Fatalf("%s: error=%v, want %v", name, err, want)
		}
		after := snapshotReleaseTree(t, root)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("%s mutated the release root\nbefore=%v\nafter=%v", name, before, after)
		}
	}

	allowed, _ := buildExplicitFixture(t, 3, "v9.2.0", "any", "ssh.tar.gz", "third")
	allowedSigned, err := SignManifest(allowed, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	assertUnchanged("allowed", func() error { return CheckPublishPolicy(root, allowedSigned, publicKey) }, nil)

	conflict, _ := buildExplicitFixture(t, 3, "v9.0.0", "any", "ssh.tar.gz", "rebound")
	conflictSigned, err := SignManifest(conflict, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	assertUnchanged("version conflict", func() error { return CheckPublishPolicy(root, conflictSigned, publicKey) }, ErrVersionConflict)

	rollback, _ := buildExplicitFixture(t, 1, "v8.9.0", "any", "ssh.tar.gz", "rollback")
	rollbackSigned, err := SignManifest(rollback, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	assertUnchanged("rollback", func() error { return CheckPublishPolicy(root, rollbackSigned, publicKey) }, ErrReleaseRollback)

	if err := os.Chmod(filepath.Join(root, "history"), 0o777); err != nil {
		t.Fatal(err)
	}
	assertUnchanged("unsafe history", func() error { return CheckPublishPolicy(root, allowedSigned, publicKey) }, ErrUnsafePath)
}

func TestPublishResumeRejectsWritableSetAncestors(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	manifest, paths := buildExplicitFixture(t, 1, "v9.3.0", "any", "ssh.tar.gz", "committed")
	signed, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, signed, paths, publicKey); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "history")); err != nil {
		t.Fatal(err)
	}
	for _, source := range paths {
		if err := os.Remove(source); err != nil {
			t.Fatal(err)
		}
	}
	setPath := filepath.Join(root, "sets", strings.TrimPrefix(manifest.SetID, "sha256:"))
	artifactAncestor := filepath.Dir(filepath.Join(setPath, "artifacts", filepath.FromSlash(manifest.Components[0].Artifact)))
	for _, test := range []struct {
		name string
		path string
	}{
		{name: "set", path: setPath},
		{name: "artifact ancestor", path: artifactAncestor},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Chmod(test.path, 0o777); err != nil {
				t.Fatal(err)
			}
			if err := Publish(root, signed, paths, publicKey); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("error=%v, want ErrUnsafePath", err)
			}
			if _, err := os.Lstat(filepath.Join(root, "current")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe resume changed current: %v", err)
			}
			if err := os.Chmod(test.path, 0o755); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := Publish(root, signed, paths, publicKey); err != nil {
		t.Fatalf("secure source-less resume: %v", err)
	}
	current, _, err := Current(root, publicKey)
	if err != nil || current.Manifest.SetID != manifest.SetID {
		t.Fatalf("source-less resume current=%s err=%v, want %s", current.Manifest.SetID, err, manifest.SetID)
	}
}

func TestCheckPublishPolicyRejectsOperationalFilesystemBlockers(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	manifest, paths := buildExplicitFixture(t, 1, "v9.4.0", "any", "ssh.tar.gz", "candidate")
	signed, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("missing root below read-only parent", func(t *testing.T) {
		parent := t.TempDir()
		if err := os.Chmod(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(parent, 0o700)
		root := filepath.Join(parent, "missing")
		if err := CheckPublishPolicy(root, signed, publicKey); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("error=%v, want ErrUnsafePath", err)
		}
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("plan created missing root: %v", err)
		}
	})

	t.Run("read-only existing root", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "release-root")
		if err := Publish(root, signed, paths, publicKey); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(root, 0o750)
		if err := CheckPublishPolicy(root, signed, publicKey); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("error=%v, want ErrUnsafePath", err)
		}
	})

	t.Run("unsafe publish lock", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "release-root")
		if err := Publish(root, signed, paths, publicKey); err != nil {
			t.Fatal(err)
		}
		lockPath := filepath.Join(root, ".publish.lock")
		if err := os.Chmod(lockPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := CheckPublishPolicy(root, signed, publicKey); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("error=%v, want ErrUnsafePath", err)
		}
	})

	t.Run("non-sticky writable ancestor", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "writable")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(parent, "release-root")
		if err := CheckPublishPolicy(root, signed, publicKey); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("plan error=%v, want ErrUnsafePath", err)
		}
		if err := Publish(root, signed, paths, publicKey); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("publish error=%v, want ErrUnsafePath", err)
		}
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unsafe ancestor publish created root: %v", err)
		}
	})

	t.Run("sticky writable ancestor", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "sticky")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o777|os.ModeSticky); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(parent, "release-root")
		if err := CheckPublishPolicy(root, signed, publicKey); err != nil {
			t.Fatalf("sticky plan: %v", err)
		}
		if err := Publish(root, signed, paths, publicKey); err != nil {
			t.Fatalf("sticky publish: %v", err)
		}
	})
}

func TestReleaseRootIdentityDetectsRenameSwap(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "release-root")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	expected, err := validatePublishedDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(parent, "moved-root")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := ensureReleaseRootIdentity(root, expected); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("error=%v, want ErrUnsafePath", err)
	}
}

func TestVersionBindingsAreIndependentPerTarget(t *testing.T) {
	buildFlow := func(generation uint64, includeArm bool, armContents string) Manifest {
		t.Helper()
		directory := t.TempDir()
		amd64 := filepath.Join(directory, "amd64")
		if err := os.WriteFile(amd64, []byte("amd64 bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		inputs := []ArtifactInput{{Component: "flow", Version: "v7.0.0", Target: "linux-amd64", ArtifactName: "flow", SourcePath: amd64}}
		if includeArm {
			arm64 := filepath.Join(directory, "arm64")
			if err := os.WriteFile(arm64, []byte(armContents), 0o600); err != nil {
				t.Fatal(err)
			}
			inputs = append(inputs, ArtifactInput{Component: "flow", Version: "v7.0.0", Target: "linux-arm64", ArtifactName: "flow", SourcePath: arm64})
		}
		manifest, err := BuildFromArtifacts(generation, inputs, []Profile{{Name: "flow", Components: []string{"flow"}}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return manifest
	}

	amdOnly := buildFlow(1, false, "")
	withNewArm := buildFlow(2, true, "arm64 first bytes")
	history := make(map[string]immutableVersionBinding)
	if err := registerVersionBindings(history, amdOnly); err != nil {
		t.Fatal(err)
	}
	if err := registerVersionBindings(history, withNewArm); err != nil {
		t.Fatalf("new target was rejected: %v", err)
	}
	changedArm := buildFlow(3, true, "arm64 changed bytes")
	if err := registerVersionBindings(history, changedArm); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("error=%v, want arm64 ErrVersionConflict", err)
	}
}

func TestManifestDirectBindingTamperAndWrongKey(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := testKeys(t)
	manifest, paths := buildFixture(t, 1, "release-one")
	signed, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(signed, publicKey); err != nil {
		t.Fatal(err)
	}
	tampered := signed
	tampered.Manifest.Components = append([]Component(nil), signed.Manifest.Components...)
	tampered.Manifest.Components[0].Target = "linux-amd64"
	if err := VerifyManifest(tampered, publicKey); err == nil {
		t.Fatal("target tamper was accepted")
	}
	otherPublic, _, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(signed, otherPublic); err == nil {
		t.Fatal("wrong signing key was accepted")
	}
	if err := os.WriteFile(paths[manifest.Components[0].Artifact], []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifacts(manifest, paths); !errors.Is(err, ErrArtifactTampered) {
		t.Fatalf("artifact tamper error = %v", err)
	}
}

func TestBuildIsCanonicalAndRejectsActiveRevocation(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	one := filepath.Join(directory, "one")
	two := filepath.Join(directory, "two")
	if err := os.WriteFile(one, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(two, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	inputs := []ArtifactInput{
		{Component: "vpn", Version: "v2.0.0", Target: "any", ArtifactName: "vpn.tar.gz", SourcePath: two},
		{Component: "ssh", Version: "v1.0.0", Target: "any", ArtifactName: "ssh.tar.gz", SourcePath: one},
	}
	profiles := []Profile{{Name: "pbp", DependsOn: []string{"vpn", "ssh"}, Components: []string{"vpn"}}, {Name: "ssh", Components: []string{"ssh"}}, {Name: "vpn", Components: []string{"vpn"}}}
	first, err := BuildFromArtifacts(7, inputs, profiles, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildFromArtifacts(7, []ArtifactInput{inputs[1], inputs[0]}, []Profile{profiles[2], profiles[1], profiles[0]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.SetID != second.SetID {
		t.Fatalf("set IDs differ: %s != %s", first.SetID, second.SetID)
	}
	first.Revocations = []Revocation{{Component: "ssh", Version: "v1.0.0", Reason: "revoked"}}
	first = normalize(first)
	first.SetID, err = ComputeSetID(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(first); err == nil {
		t.Fatal("active revoked component was accepted")
	}
}

func TestPrivateKeyMarkersRemainEffectiveAcrossWriteBoundaries(t *testing.T) {
	for _, kind := range []string{"", "ENCRYPTED ", "OPENSSH ", "RSA ", "EC ", "DSA "} {
		t.Run(strings.TrimSpace(kind), func(t *testing.T) {
			detector := &privateKeyDetector{}
			first := []byte("noise-----BEGIN " + kind + "PRI")
			second := []byte("VATE KEY-----tail")
			if _, err := detector.Write(first); err != nil {
				t.Fatal(err)
			}
			if detector.found {
				t.Fatal("partial marker was accepted as complete")
			}
			if _, err := detector.Write(second); err != nil {
				t.Fatal(err)
			}
			if !detector.found {
				t.Fatalf("%q private-key marker was not detected across writes", kind)
			}
		})
	}
}

func TestBuiltFlowArtifactDoesNotSelfMatchPrivateKeyMarkers(t *testing.T) {
	repository := filepath.Clean(filepath.Join("..", ".."))
	binary := filepath.Join(t.TempDir(), "flow")
	// Keep source-archive builds independent of surrounding Git metadata.
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", binary, "./cmd/flow")
	command.Dir = repository
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build flow: %v: %s", err, output)
	}
	_, err := BuildFromArtifacts(1, []ArtifactInput{{
		Component: "flow", Version: "v0.1.0", Target: "linux-amd64",
		ArtifactName: "flow", SourcePath: binary,
	}}, []Profile{{Name: "ssh", Components: []string{"flow"}}}, nil)
	if err != nil {
		t.Fatalf("flow binary rejected as its own release artifact: %v", err)
	}
}

func TestManifestRejectsDuplicateProfileEdges(t *testing.T) {
	t.Parallel()
	manifest, _ := buildFixture(t, 1, "release")
	manifest.Profiles[0].Components = []string{"ssh", "ssh"}
	manifest = normalize(manifest)
	var err error
	manifest.SetID, err = ComputeSetID(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(manifest); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("duplicate profile component: got %v, want ErrInvalidManifest", err)
	}
}

func TestManifestRejectsOversizedVersionAndControlReason(t *testing.T) {
	manifest, _ := buildFixture(t, 1, "release")
	manifest.Revocations[0].Version = "v1.2.3-" + strings.Repeat("a", maxNameBytes)
	manifest = normalize(manifest)
	manifest.SetID, _ = ComputeSetID(manifest)
	if err := Validate(manifest); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("oversized version: %v", err)
	}
	manifest, _ = buildFixture(t, 1, "release")
	manifest.Revocations[0].Reason = "line-one\nline-two"
	manifest = normalize(manifest)
	manifest.SetID, _ = ComputeSetID(manifest)
	if err := Validate(manifest); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("control-character reason: %v", err)
	}
}

func TestPublishRejectsSymlinkedRootAncestor(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := testKeys(t)
	manifest, paths := buildFixture(t, 1, "release")
	signed, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	realDirectory := t.TempDir()
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Fatal(err)
	}
	if err := Publish(filepath.Join(link, "releases"), signed, paths, publicKey); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlinked root ancestor: got %v, want ErrUnsafePath", err)
	}
}

func TestArtifactHashRejectsSymlinkAncestorAndHardlink(t *testing.T) {
	t.Parallel()
	realRoot := t.TempDir()
	artifact := filepath.Join(realRoot, "artifact.tar")
	if err := os.WriteFile(artifact, []byte("artifact\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedRoot := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if _, _, err := hashFile(filepath.Join(linkedRoot, "artifact.tar")); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlinked ancestor hash: got %v, want ErrUnsafePath", err)
	}
	hardlink := filepath.Join(realRoot, "artifact-copy.tar")
	if err := os.Link(artifact, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := hashFile(artifact); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("hardlinked artifact hash: got %v, want ErrUnsafePath", err)
	}
}

func TestPublishAndCurrentAreAtomicAndTamperEvident(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	manifestOne, pathsOne := buildFixture(t, 1, "release-one")
	signedOne, err := SignManifest(manifestOne, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, signedOne, pathsOne, publicKey); err != nil {
		t.Fatal(err)
	}
	current, setPath, err := Current(root, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if current.Manifest.SetID != manifestOne.SetID {
		t.Fatal("wrong current set")
	}
	for _, publishedPath := range []string{
		filepath.Join(setPath, "signed-manifest.json"),
		filepath.Join(setPath, "artifacts", filepath.FromSlash(manifestOne.Components[0].Artifact)),
	} {
		info, err := os.Lstat(publishedPath)
		if err != nil {
			t.Fatalf("inspect published immutable file %s: %v", publishedPath, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 {
			t.Fatalf("published immutable file %s mode/type=%v", publishedPath, info.Mode())
		}
	}

	manifestTwo, pathsTwo := buildFixture(t, 2, "release-two")
	signedTwo, err := SignManifest(manifestTwo, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, signedTwo, pathsTwo, publicKey); err != nil {
		t.Fatal(err)
	}
	current, _, err = Current(root, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if current.Manifest.SetID != manifestTwo.SetID {
		t.Fatal("current pointer was not updated")
	}

	artifact := filepath.Join(setPath, "artifacts", filepath.FromSlash(manifestOne.Components[0].Artifact))
	if err := os.Chmod(artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(artifact, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.ToSlash(filepath.Join("sets", manifestOne.SetID[len("sha256:"):])), filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Current(root, publicKey); !errors.Is(err, ErrArtifactTampered) {
		t.Fatalf("published tamper error = %v", err)
	}
}

func TestOpenSetRetainsVerifiedPredecessorAfterCurrentAdvances(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	manifestOne, pathsOne := buildFixture(t, 1, "release-one")
	signedOne, err := SignManifest(manifestOne, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, signedOne, pathsOne, publicKey); err != nil {
		t.Fatal(err)
	}
	manifestTwo, pathsTwo := buildFixture(t, 2, "release-two")
	signedTwo, err := SignManifest(manifestTwo, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, signedTwo, pathsTwo, publicKey); err != nil {
		t.Fatal(err)
	}
	retained, retainedPath, err := OpenSet(root, manifestOne.SetID, publicKey)
	if err != nil {
		t.Fatalf("open retained predecessor: %v", err)
	}
	if retained.Manifest.SetID != manifestOne.SetID || filepath.Base(retainedPath) != strings.TrimPrefix(manifestOne.SetID, "sha256:") {
		t.Fatalf("retained set/path mismatch: %s %s", retained.Manifest.SetID, retainedPath)
	}
	current, _, err := Current(root, publicKey)
	if err != nil || current.Manifest.SetID != manifestTwo.SetID {
		t.Fatalf("current set=%s err=%v", current.Manifest.SetID, err)
	}
}

func TestOpenSetRejectsNonCanonicalAndTraversalIDs(t *testing.T) {
	t.Parallel()
	publicKey, _ := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, setID := range []string{
		"", "sha256:../" + strings.Repeat("a", 61), "sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("a", 63), "sha512:" + strings.Repeat("a", 64),
	} {
		if _, _, err := OpenSet(root, setID, publicKey); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("set ID %q: got %v, want ErrUnsafePath", setID, err)
		}
	}
}

func TestOpenSetRejectsLinkedOrWritablePublishedManifest(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, manifestPath string)
	}{
		{
			name: "symlink",
			mutate: func(t *testing.T, manifestPath string) {
				t.Helper()
				copyPath := filepath.Join(t.TempDir(), "manifest.json")
				data, err := os.ReadFile(manifestPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(copyPath, data, 0o444); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(manifestPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(copyPath, manifestPath); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hardlink",
			mutate: func(t *testing.T, manifestPath string) {
				t.Helper()
				if err := os.Link(manifestPath, manifestPath+".link"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "writable",
			mutate: func(t *testing.T, manifestPath string) {
				t.Helper()
				if err := os.Chmod(manifestPath, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			publicKey, privateKey := testKeys(t)
			root := filepath.Join(t.TempDir(), "release-root")
			manifest, paths := buildFixture(t, 1, "release")
			signed, err := SignManifest(manifest, privateKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := Publish(root, signed, paths, publicKey); err != nil {
				t.Fatal(err)
			}
			_, setPath, err := Current(root, publicKey)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(t, filepath.Join(setPath, "signed-manifest.json"))
			if _, _, err := OpenSet(root, manifest.SetID, publicKey); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("unsafe published manifest: got %v, want ErrUnsafePath", err)
			}
		})
	}
}

func TestConcurrentIdempotentPublish(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	manifest, paths := buildFixture(t, 1, "same-release")
	signed, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errorsChannel := make(chan error, 12)
	for index := 0; index < 12; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsChannel <- Publish(root, signed, paths, publicKey)
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Errorf("concurrent publish: %v", err)
		}
	}
	if _, _, err := Current(root, publicKey); err != nil {
		t.Fatal(err)
	}
}

func TestPublishRejectsSignatureBeforeCreatingCurrent(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := testKeys(t)
	manifest, paths := buildFixture(t, 1, "release")
	signed, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	signed.Signature.Value[0] ^= 0xff
	root := filepath.Join(t.TempDir(), "release-root")
	if err := Publish(root, signed, paths, publicKey); err == nil {
		t.Fatal("bad signature was published")
	}
	if _, err := os.Lstat(filepath.Join(root, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("current exists after rejected publish: %v", err)
	}
}

func TestPublishRefusesLowerAndEqualDifferentGeneration(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	currentManifest, currentPaths := buildFixture(t, 2, "generation-two")
	currentSigned, err := SignManifest(currentManifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, currentSigned, currentPaths, publicKey); err != nil {
		t.Fatal(err)
	}
	lowerManifest, lowerPaths := buildFixture(t, 1, "generation-one")
	lowerSigned, err := SignManifest(lowerManifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, lowerSigned, lowerPaths, publicKey); !errors.Is(err, ErrReleaseRollback) {
		t.Fatalf("lower generation: got %v, want ErrReleaseRollback", err)
	}
	equalManifest, equalPaths := buildFixture(t, 2, "generation-two-different")
	equalSigned, err := SignManifest(equalManifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, equalSigned, equalPaths, publicKey); !errors.Is(err, ErrReleaseRollback) {
		t.Fatalf("equal generation with different set: got %v, want ErrReleaseRollback", err)
	}
	if err := Publish(root, currentSigned, currentPaths, publicKey); err != nil {
		t.Fatalf("idempotent equal generation: %v", err)
	}
	current, _, err := Current(root, publicKey)
	if err != nil || current.Manifest.SetID != currentManifest.SetID {
		t.Fatalf("current set=%s err=%v, want %s", current.Manifest.SetID, err, currentManifest.SetID)
	}
}

func TestConcurrentPublishAcrossGenerationsEndsAtHighest(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	first, firstPaths := buildFixture(t, 1, "generation-one")
	firstSigned, err := SignManifest(first, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, firstSigned, firstPaths, publicKey); err != nil {
		t.Fatal(err)
	}
	second, secondPaths := buildFixture(t, 2, "generation-two")
	secondSigned, err := SignManifest(second, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	third, thirdPaths := buildFixture(t, 3, "generation-three")
	thirdSigned, err := SignManifest(third, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() { <-start; results <- Publish(root, secondSigned, secondPaths, publicKey) }()
	go func() { <-start; results <- Publish(root, thirdSigned, thirdPaths, publicKey) }()
	close(start)
	for attempt := 0; attempt < 2; attempt++ {
		result := <-results
		if result != nil && !errors.Is(result, ErrReleaseRollback) {
			t.Fatalf("concurrent generation publish: %v", result)
		}
	}
	current, _, err := Current(root, publicKey)
	if err != nil || current.Manifest.Generation != 3 || current.Manifest.SetID != third.SetID {
		t.Fatalf("current generation=%d set=%s err=%v, want generation 3 set %s", current.Manifest.Generation, current.Manifest.SetID, err, third.SetID)
	}
}

func TestPublishRejectsSymlinkLock(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := testKeys(t)
	manifest, paths := buildFixture(t, 1, "release")
	signed, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "release-root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "lock-target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, ".publish.lock")); err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, signed, paths, publicKey); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink publish lock: got %v, want ErrUnsafePath", err)
	}
}

func TestPublishRetainedSetsAreTheHighWaterAuthority(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	root := filepath.Join(t.TempDir(), "release-root")
	manifests := make([]Manifest, 4)
	paths := make([]map[string]string, 4)
	signed := make([]SignedManifest, 4)
	for _, generation := range []int{1, 2, 3} {
		manifests[generation], paths[generation] = buildFixture(t, uint64(generation), "generation-"+string(rune('0'+generation)))
		var err error
		signed[generation], err = SignManifest(manifests[generation], privateKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := Publish(root, signed[1], paths[1], publicKey); err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, signed[3], paths[3], publicKey); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	oneName := strings.TrimPrefix(manifests[1].SetID, "sha256:")
	if err := os.Symlink("sets/"+oneName, filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, signed[2], paths[2], publicKey); !errors.Is(err, ErrReleaseRollback) {
		t.Fatalf("rewound current bypassed retained high-water: %v", err)
	}
	if err := Publish(root, signed[3], paths[3], publicKey); err != nil {
		t.Fatalf("idempotent retained high-water could not restore current: %v", err)
	}
	current, _, err := Current(root, publicKey)
	if err != nil || current.Manifest.SetID != manifests[3].SetID {
		t.Fatalf("current=%s err=%v, want retained generation 3", current.Manifest.SetID, err)
	}
}

func TestPublishedArtifactRequiresImmutableMode(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	manifest, paths := buildFixture(t, 1, "release")
	signed, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "release-root")
	if err := Publish(root, signed, paths, publicKey); err != nil {
		t.Fatal(err)
	}
	_, setPath, err := Current(root, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(setPath, "artifacts", filepath.FromSlash(manifest.Components[0].Artifact))
	if err := os.Chmod(artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Current(root, publicKey); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("writable retained artifact: got %v, want ErrUnsafePath", err)
	}
}

func TestPublishRejectsHardlinkedLockWithoutMutatingTarget(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	manifest, paths := buildFixture(t, 1, "release")
	signed, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "release-root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "lock-target")
	if err := os.WriteFile(target, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, filepath.Join(root, ".publish.lock")); err != nil {
		t.Fatal(err)
	}
	if err := Publish(root, signed, paths, publicKey); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("hardlinked publish lock: got %v, want ErrUnsafePath", err)
	}
	info, err := os.Stat(target)
	data, readErr := os.ReadFile(target)
	if err != nil || readErr != nil || info.Mode().Perm() != 0o600 || string(data) != "sentinel" {
		t.Fatalf("lock target was mutated: mode=%v err=%v", info.Mode(), err)
	}
}

func TestCurrentRejectsHardlinkedPointer(t *testing.T) {
	publicKey, privateKey := testKeys(t)
	manifest, paths := buildFixture(t, 1, "release")
	signed, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "release-root")
	if err := Publish(root, signed, paths, publicKey); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "current"), filepath.Join(root, "current-held")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Current(root, publicKey); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("hardlinked current pointer: got %v, want ErrUnsafePath", err)
	}
}

func TestManifestAndBundleBounds(t *testing.T) {
	manifest, _ := buildFixture(t, 1, "release")
	manifest.Components[0].Size = MaxBundleBytes + 1
	manifest.SetID, _ = ComputeSetID(manifest)
	if err := Validate(manifest); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("oversized artifact manifest: %v", err)
	}

	manifest, _ = buildFixture(t, 1, "release")
	manifest.Components[0].Size = MaxBundleBytes
	manifest.SetID, _ = ComputeSetID(manifest)
	publicKey, privateKey := testKeys(t)
	signed, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BundleSize(signed); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("bundle framing overflow bound: %v", err)
	}
	if err := VerifyManifest(signed, publicKey); err != nil {
		t.Fatalf("bounded manifest signature unexpectedly invalid: %v", err)
	}
}
