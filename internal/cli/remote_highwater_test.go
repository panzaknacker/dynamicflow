package cli

import (
	"strings"
	"testing"

	"dynamicflow/internal/localstate"
	"dynamicflow/internal/release"
)

func TestOperatorReleaseHighWaterRejectsRollbackAndGenerationConflict(t *testing.T) {
	store, err := localstate.Open(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &commandContext{store: store}
	setFive := "sha256:" + strings.Repeat("5", 64)
	setSix := "sha256:" + strings.Repeat("6", 64)
	if err := acceptOperatorReleaseHighWater(ctx, release.Manifest{Generation: 5, SetID: setFive}); err != nil {
		t.Fatal(err)
	}
	if err := acceptOperatorReleaseHighWater(ctx, release.Manifest{Generation: 5, SetID: setFive}); err != nil {
		t.Fatalf("idempotent high-water check failed: %v", err)
	}
	if err := acceptOperatorReleaseHighWater(ctx, release.Manifest{
		Generation: 4, SetID: "sha256:" + strings.Repeat("4", 64),
	}); err == nil || !strings.Contains(err.Error(), "below pinned") {
		t.Fatalf("release rollback accepted: %v", err)
	}
	if err := acceptOperatorReleaseHighWater(ctx, release.Manifest{
		Generation: 5, SetID: "sha256:" + strings.Repeat("a", 64),
	}); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("equal-generation conflict accepted: %v", err)
	}
	if err := acceptOperatorReleaseHighWater(ctx, release.Manifest{Generation: 6, SetID: setSix}); err != nil {
		t.Fatal(err)
	}
	var persisted operatorReleaseHighWater
	if err := store.ReadJSON(operatorReleaseHighWaterPath, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Generation != 6 || persisted.SetID != setSix {
		t.Fatalf("high-water state = %#v", persisted)
	}
}
