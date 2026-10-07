package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequestedCommandIDKeepsExtendedManagementActions(t *testing.T) {
	const input = "private-context-must-not-enter-command-id"
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"system", "select", input}, "system.select"},
		{[]string{"control", "apply", input}, "control.apply"},
		{[]string{"control", "attest", input}, "control.attest"},
		{[]string{"control-runtime", "install", input}, "control-runtime.install"},
		{[]string{"control-runtime", "session", input}, "control-runtime.session"},
		{[]string{"system", input}, "system"},
		{[]string{"control", input}, "control"},
		{[]string{"control-runtime", input}, "control-runtime"},
	} {
		t.Run(strings.Join(test.args[:2], "."), func(t *testing.T) {
			got := requestedCommandID(test.args)
			if got != test.want || strings.Contains(got, input) {
				t.Fatalf("requestedCommandID(%q)=%q, want %q", test.args, got, test.want)
			}
		})
	}
}

func TestRuntimeFailureCommandIDsIgnoreUnknownActions(t *testing.T) {
	const input = "private-context-must-not-enter-command-id"
	for _, group := range []string{"instance-runtime", "control-runtime"} {
		t.Run(group, func(t *testing.T) {
			status, stdout, stderr := invokeCLI(t, "--json", group, input)
			if status != exitUsage || stdout != "" {
				t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			envelope := decodeCLIEnvelope(t, stderr)
			if envelope.Command != group || strings.Contains(envelope.Command, input) {
				t.Fatalf("command ID=%q, want %q", envelope.Command, group)
			}
		})
	}
}

func TestRuntimeHelpAliasesRemainStateFree(t *testing.T) {
	home := filepath.Join(t.TempDir(), "unopened-operator")
	t.Setenv("FLOW_HOME", home)
	t.Setenv("FLOW_PROFILES_DIR", filepath.Join(t.TempDir(), "unopened-profiles"))
	for _, group := range []string{"instance-runtime", "control-runtime"} {
		for _, alias := range []string{"help", "--help", "-h"} {
			t.Run(group+"."+alias, func(t *testing.T) {
				status, stdout, stderr := invokeCLI(t, group, alias)
				if status != exitOK || stderr != "" || !strings.Contains(stdout, group) {
					t.Fatalf("help status=%d stdout=%q stderr=%q", status, stdout, stderr)
				}
				if _, err := os.Lstat(home); !os.IsNotExist(err) {
					t.Fatalf("runtime help opened operator state: %v", err)
				}
			})
		}
	}
}
