package cli

import (
	"flag"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestInterspersedParserSupportsOptionsAroundName(t *testing.T) {
	set := flag.NewFlagSet("fixture", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	gui := set.Bool("gui", false, "")
	port := set.Int("local-port", 5901, "")
	if err := parseInterspersed(set, []string{"pbp-01", "--gui", "--local-port", "5902"}); err != nil {
		t.Fatal(err)
	}
	if !*gui || *port != 5902 || !reflect.DeepEqual(set.Args(), []string{"pbp-01"}) {
		t.Fatalf("gui=%t port=%d operands=%v", *gui, *port, set.Args())
	}
}

func TestInternalInstanceHandlersAcceptDocumentedInterspersedOptions(t *testing.T) {
	home := privateTempDir(t)
	tests := []struct {
		name string
		args []string
		want int
		code string
	}{
		{
			"ssh gui after name",
			[]string{"--home", home, "instance", "ssh", "missing", "--gui"},
			exitConfig, "ssh",
		},
		{
			"ssh options on both sides",
			[]string{"--home", home, "instance", "ssh", "--gui", "missing", "--local-port", "5902"},
			exitConfig, "ssh",
		},
		{
			"secret reveal after name",
			[]string{"--json", "--home", home, "instance", "secret", "reveal", "missing", "--secret", "vnc"},
			exitConfig, "ssh",
		},
		{
			"secret rotate equals form and trailing JSON",
			[]string{"--home", home, "instance", "secret", "rotate", "missing", "--secret=vnc", "--json"},
			exitConfig, "ssh",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, stdout, stderr := invokeInternalLegacyHandlerForTest(t, test.args...)
			if status != test.want {
				t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			if strings.Contains(strings.Join(test.args, " "), "--json") {
				if stdout != "" {
					t.Fatalf("JSON failure wrote stdout: %q", stdout)
				}
				envelope := decodeCLIEnvelope(t, stderr)
				if envelope.Error == nil || envelope.Error.Code != test.code {
					t.Fatalf("JSON failure = %+v", envelope)
				}
			} else if !strings.Contains(stderr, "ERROR ["+test.code+"]") {
				t.Fatalf("human error = %q", stderr)
			}
		})
	}
}

func TestInternalInterspersedParserRejectsAmbiguityAsSingleJSONError(t *testing.T) {
	home := privateTempDir(t)
	tests := [][]string{
		{"--json", "--home", home, "instance", "ssh", "node", "--gui", "--gui"},
		{"--home", home, "instance", "ssh", "node", "--local-port", "5902", "--json"},
		{"--json", "--home", home, "instance", "ssh", "node", "--unknown"},
		{"--json", "--home", home, "instance", "secret", "reveal", "node", "--secret"},
		{"--json", "--home", home, "instance", "secret", "rotate", "node", "--secret", "vnc", "--secret=vnc"},
	}
	for _, arguments := range tests {
		status, stdout, stderr := invokeInternalLegacyHandlerForTest(t, arguments...)
		if status != exitUsage || stdout != "" {
			t.Errorf("args=%v status=%d stdout=%q stderr=%q", arguments, status, stdout, stderr)
			continue
		}
		envelope := decodeCLIEnvelope(t, stderr)
		if envelope.Error == nil || envelope.Error.Code != "usage" {
			t.Errorf("args=%v envelope=%+v", arguments, envelope)
		}
	}
}

func TestGlobalJSONStopsAtExplicitExecSeparator(t *testing.T) {
	global, arguments, err := parseGlobal([]string{"instance", "exec", "node", "--", "printf", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if global.json {
		t.Fatal("remote --json was consumed as a global option")
	}
	want := []string{"instance", "exec", "node", "--", "printf", "--json"}
	if !reflect.DeepEqual(arguments, want) {
		t.Fatalf("arguments=%v, want %v", arguments, want)
	}

	global, arguments, err = parseGlobal([]string{"instance", "secret", "reveal", "node", "--secret", "vnc", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if !global.json {
		t.Fatal("documented trailing global --json was not recognized")
	}
	want = []string{"instance", "secret", "reveal", "node", "--secret", "vnc"}
	if !reflect.DeepEqual(arguments, want) {
		t.Fatalf("arguments=%v, want %v", arguments, want)
	}
}

func TestInternalInteractiveSSHRejectsTrailingGlobalJSONAfterParsingOptions(t *testing.T) {
	status, stdout, stderr := invokeInternalLegacyHandlerForTest(t,
		"--home", privateTempDir(t), "instance", "ssh", "missing", "--gui", "--json",
	)
	if status != exitUsage || stdout != "" {
		t.Fatalf("status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	envelope := decodeCLIEnvelope(t, stderr)
	if envelope.Error == nil || !strings.Contains(envelope.Error.Message, "interactive SSH") {
		t.Fatalf("interactive JSON error = %+v", envelope)
	}
}
