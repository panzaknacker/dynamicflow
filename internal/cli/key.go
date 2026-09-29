package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dynamicflow/internal/sshkeys"
)

func commandKey(ctx *commandContext, args []string) int {
	if len(args) == 0 {
		return usage(ctx, "usage: flow key <create|list|rotate|revoke>")
	}
	manager := sshkeys.NewManager(ctx.store)
	switch args[0] {
	case "create", "rotate", "revoke":
		flags := newCommandFlagSet(ctx, "key "+args[0])
		name := flags.String("name", "", "key name")
		scopeValue := flags.String("scope", string(sshkeys.Operator), "operator or instance")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *name == "" {
			return usage(ctx, "usage: flow key "+args[0]+" --name NAME [--scope operator|instance]")
		}
		scope := sshkeys.Scope(*scopeValue)
		var record sshkeys.Record
		var err error
		ctx.out.phase("key", "running", args[0]+" "+*name)
		switch args[0] {
		case "create":
			operation, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			record, err = manager.Create(operation, scope, *name)
		case "rotate":
			operation, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if scope == sshkeys.Instance {
				expected, bound, bindingErr := boundInstanceKeyRotation(ctx, *name)
				if bindingErr != nil {
					err = bindingErr
				} else if bound {
					record, err = manager.RotateIfGeneration(operation, scope, *name, expected)
				} else {
					record, err = manager.Rotate(operation, scope, *name)
				}
			} else {
				record, err = manager.Rotate(operation, scope, *name)
			}
		case "revoke":
			record, err = manager.Revoke(scope, *name)
		}
		if err != nil {
			audit(ctx, "key."+args[0], "failure", map[string]any{"name": *name, "scope": scope, "error": err.Error()})
			return ctx.out.fail("key", err.Error(), "Inspect public key metadata with flow key list.", exitConflict)
		}
		audit(ctx, "key."+args[0], "success", map[string]any{"name": record.Name, "scope": record.Scope, "generation": record.Generation, "fingerprint": record.Fingerprint})
		human := fmt.Sprintf("%s key %s generation %d: %s", strings.Title(args[0]), record.Name, record.Generation, record.Fingerprint)
		return ctx.out.success("key."+args[0], record, human)
	case "list":
		flags := newCommandFlagSet(ctx, "key list")
		scopeValue := flags.String("scope", string(sshkeys.Operator), "operator or instance")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return usage(ctx, "usage: flow key list [--scope operator|instance]")
		}
		records, err := manager.List(sshkeys.Scope(*scopeValue))
		if err != nil {
			return ctx.out.fail("key", err.Error(), "Run flow init or repair local key metadata.", exitConfig)
		}
		if !ctx.out.json {
			for _, record := range records {
				fmt.Fprintf(ctx.out.stdout, "%-24s g%-3d %-8s %s\n", record.Name, record.Generation, record.Status, record.Fingerprint)
			}
			return exitOK
		}
		return ctx.out.success("key.list", records, "")
	default:
		return usage(ctx, "unknown key command: "+args[0])
	}
}

func boundInstanceKeyRotation(ctx *commandContext, keyName string) (uint64, bool, error) {
	directory, err := ctx.store.Path("enrollments")
	if err != nil {
		return 0, false, err
	}
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	var generation uint64
	found := false
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return 0, false, errors.New("unsafe enrollment metadata entry")
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		local, err := loadLocalEnrollment(ctx, name)
		if err != nil {
			return 0, false, err
		}
		if local.State == "revoked" || local.KeyScope != sshkeys.Instance || local.KeyName != keyName {
			continue
		}
		if found {
			return 0, false, errors.New("instance SSH identity has multiple live bindings")
		}
		if local.RotationPending {
			return 0, false, errors.New("instance SSH rotation is already pending finalization")
		}
		generation, found = local.KeyGeneration, true
	}
	return generation, found, nil
}
