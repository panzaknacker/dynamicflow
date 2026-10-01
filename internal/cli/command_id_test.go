package cli

import (
	"strings"
	"testing"
)

func TestPublicFailureCommandIDsContainOnlyKnownActions(t *testing.T) {
	const input = "private-input-should-not-be-a-command"
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"instance", "secret", input}, "instance.secret"},
		{[]string{"instance", "key", input}, "instance.key"},
		{[]string{"instance", "hostkey", input}, "instance.hostkey"},
		{[]string{"key", input}, "key"},
		{[]string{"control", input}, "control"},
		{[]string{"instance-runtime", input}, "instance-runtime"},
		{[]string{input}, "flow"},
	} {
		t.Run(strings.Join(test.args, "."), func(t *testing.T) {
			arguments := []string{"--json"}
			if test.args[0] != "instance-runtime" {
				arguments = append(arguments, "--home", privateTempDir(t))
			}
			arguments = append(arguments, test.args...)
			status, stdout, stderr := invokeCLI(t, arguments...)
			if status == exitOK || stdout != "" {
				t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			envelope := decodeCLIEnvelope(t, stderr)
			if envelope.Command != test.want || strings.Contains(envelope.Command, input) {
				t.Fatalf("command ID = %q, want %q", envelope.Command, test.want)
			}
		})
	}
}

func TestRequestedCommandIDKeepsKnownNestedActions(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{nil, "flow"},
		{[]string{"help", "private-input"}, "help"},
		{[]string{"instance", "secret", "reveal", "private-input"}, "instance.secret.reveal"},
		{[]string{"instance", "secret", "rotate", "private-input"}, "instance.secret.rotate"},
		{[]string{"instance", "key", "finalize", "private-input"}, "instance.key.finalize"},
		{[]string{"instance", "hostkey", "pin", "private-input"}, "instance.hostkey.pin"},
		{[]string{"instance", "hostkey", "rotate", "private-input"}, "instance.hostkey.rotate"},
		{[]string{"control", "install", "private-input"}, "control.install"},
		{[]string{"instance-runtime", "enroll", "private-input"}, "instance-runtime.enroll"},
		{[]string{"instance-runtime", "secret", "private-input"}, "instance-runtime.secret"},
	} {
		if got := requestedCommandID(test.args); got != test.want {
			t.Errorf("requestedCommandID(%q)=%q, want %q", test.args, got, test.want)
		}
	}
}
