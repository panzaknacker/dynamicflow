package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"dynamicflow/internal/localstate"
)

// invokeInternalLegacyHandlerForTest exercises implementation details that are
// retained for migration into signed via-Control transports. It intentionally
// does not call Run and therefore cannot bypass the production argv gate.
// Public contract tests must always use invokeCLI instead.
func invokeInternalLegacyHandlerForTest(t *testing.T, arguments ...string) (int, string, string) {
	t.Helper()
	global, args, err := parseGlobal(arguments)
	if err != nil || len(args) == 0 || global.help || global.version {
		t.Fatalf("invalid internal handler test invocation: args=%q err=%v", arguments, err)
	}
	root := global.home
	if root == "" {
		root = privateTempDir(t)
	}
	store, err := localstate.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot := global.sourceRoot
	if sourceRoot == "" {
		sourceRoot, _ = discoverSourceRoot()
	}
	profiles := os.Getenv("FLOW_PROFILES_DIR")
	if profiles == "" && sourceRoot != "" {
		profiles = filepath.Join(sourceRoot, "profiles")
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	emit := &emitter{json: global.json, stdout: &stdout, stderr: &stderr, command: requestedCommandID(args)}
	ctx := &commandContext{store: store, home: root, sourceRoot: sourceRoot, profiles: profiles, out: emit}
	var status int
	switch args[0] {
	case "enroll":
		status = commandEnroll(ctx, args[1:])
	case "instance":
		status = commandInstance(ctx, args[1:])
	case "release":
		status = commandRelease(ctx, args[1:])
	case "test":
		status = commandTest(ctx, args[1:])
	case "start":
		status = commandStart(ctx, args[1:])
	default:
		t.Fatalf("unsupported internal legacy handler group %q", args[0])
	}
	return status, stdout.String(), stderr.String()
}
