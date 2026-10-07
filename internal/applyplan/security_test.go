package applyplan

import (
	"go/parser"
	"go/token"
	"io/fs"
	"strconv"
	"strings"
	"testing"
)

// The planner is a trust-boundary component, not an installer. Keep network,
// process execution and filesystem mutation out of this package so callers
// cannot accidentally turn planning into an implicit privileged action.
func TestPlannerHasNoNetworkExecutionOrFilesystemMutationImports(t *testing.T) {
	parsed, err := parser.ParseDir(token.NewFileSet(), ".", func(info fs.FileInfo) bool {
		return strings.HasSuffix(info.Name(), ".go") && !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]bool{
		"io": true, "io/fs": true, "net": true, "net/http": true, "net/url": true,
		"os": true, "os/exec": true, "path/filepath": true, "syscall": true,
	}
	for _, parsedPackage := range parsed {
		for filename, file := range parsedPackage.Files {
			for _, imported := range file.Imports {
				path, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if forbidden[path] {
					t.Fatalf("apply planner file %s imports forbidden side-effect package %q", filename, path)
				}
			}
		}
	}
}
