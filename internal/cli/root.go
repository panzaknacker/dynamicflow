// package cli implements dynamicflow's single operator command surface.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/x/term"

	"dynamicflow/internal/application"
	"dynamicflow/internal/localstate"
	"dynamicflow/internal/tui"
)

const Version = "0.3.0-dev"

const (
	exitOK       = 0
	exitFailure  = 1
	exitUsage    = 2
	exitConfig   = 3
	exitAuth     = 4
	exitVerify   = 5
	exitConflict = 6
	exitRemote   = 7
	exitPartial  = 8
)

type commandContext struct {
	store      *localstate.Store
	home       string
	sourceRoot string
	profiles   string
	out        *emitter
}

func Run(arguments []string, stdout, stderr io.Writer) int {
	return RunWithIO(arguments, os.Stdin, stdout, stderr)
}

func RunWithIO(arguments []string, stdin io.Reader, stdout, stderr io.Writer) int {
	global, args, err := parseGlobal(arguments)
	emit := &emitter{json: global.json, stdout: stdout, stderr: stderr, command: "flow"}
	if err != nil {
		return emit.fail("usage", err.Error(), "Run flow --help.", exitUsage)
	}
	emit.command = requestedCommandID(args)
	if global.version {
		return emit.success("version", map[string]any{"version": Version}, "flow "+Version)
	}
	if global.help {
		return emitHelp(emit, "root", helpText)
	}
	launchTUI := len(args) == 0 || (len(args) == 1 && args[0] == "tui")
	if len(args) == 0 && global.json {
		args = []string{"dashboard"}
		emit.command = "dashboard"
		launchTUI = false
	}
	if launchTUI && !interactiveTerminal(stdin, stdout) {
		return emit.fail("tty_required", "the Dynamicflow terminal UI requires TTY stdin and stdout", "Run flow --help or use a command with --json.", exitUsage)
	}
	if len(args) == 1 && args[0] == "help" {
		return emitHelp(emit, "root", helpText)
	}
	if text, ok := commandGroupHelp(args); ok {
		return emitHelp(emit, helpTopic(args), text)
	}
	if topic, text, ok := commandLeafHelp(args); ok {
		return emitHelp(emit, topic, text)
	}
	// the systemd serving entry point consumes only an absolute, root-created
	// config and deliberately does not open operator-local state.
	if len(args) > 0 && args[0] == "serve" {
		return commandServeRaw(args[1:], stdout, stderr, global.json)
	}
	// target-runtime commands must never inspect FLOW_HOME, operator keys,
	// profiles, or source state. their complete public configuration is passed
	// explicitly and credentials come only from TTY/stdin.
	if len(args) > 0 && args[0] == "instance-runtime" {
		if global.home != "" || global.sourceRoot != "" {
			return emit.fail("usage", "--home and --source-root are not valid for instance-runtime", "Use --state-root for target state.", exitUsage)
		}
		return commandInstanceRuntimeRaw(args[1:], stdout, stderr, global.json)
	}
	if topic, requested := requestedHelpTopic(args); requested {
		return emit.fail("usage", "unknown help topic: "+topic, "Run flow --help.", exitUsage)
	}
	if operatorActionNeedsControlRoute(args) {
		return emit.fail(
			controlRouteUnavailableCode,
			controlRouteUnavailableText,
			controlRouteUnavailableNext,
			exitConflict,
		)
	}
	root := global.home
	if root == "" {
		root, err = localstate.DefaultRoot()
		if err != nil {
			return emit.fail("config", err.Error(), "Set FLOW_HOME to a private local directory.", exitConfig)
		}
	}
	store, err := localstate.Open(root)
	if err != nil {
		return emit.fail("config", err.Error(), "Fix ownership/mode of FLOW_HOME.", exitConfig)
	}
	sourceRoot := global.sourceRoot
	if sourceRoot == "" {
		sourceRoot, _ = discoverSourceRoot()
	}
	profilesDir := os.Getenv("FLOW_PROFILES_DIR")
	if profilesDir == "" && sourceRoot != "" {
		profilesDir = filepath.Join(sourceRoot, "profiles")
	}
	ctx := &commandContext{store: store, home: root, sourceRoot: sourceRoot, profiles: profilesDir, out: emit}
	if launchTUI {
		app, err := application.Open(application.Config{Store: store})
		if err != nil {
			return emit.fail("system_state", err.Error(), "Repair FLOW_HOME ownership, mode or registry state.", exitConfig)
		}
		if err := tui.Run(context.Background(), app, stdin, stdout, os.Environ()); err != nil {
			failure := application.AsError(err)
			return emit.fail(failure.Code, failure.SafeText, failure.Next, failure.ExitCode)
		}
		return exitOK
	}

	switch args[0] {
	case "system":
		return commandSystem(ctx, args[1:])
	case "control":
		return commandControl(ctx, args[1:])
	case "dashboard":
		return commandDashboard(ctx, args[1:])
	case "init":
		return commandInit(ctx, args[1:])
	case "doctor":
		return commandDoctor(ctx, args[1:])
	case "key":
		return commandKey(ctx, args[1:])
	case "profile":
		return commandProfile(ctx, args[1:])
	case "release":
		return commandRelease(ctx, args[1:])
	case "serving":
		return commandServing(ctx, args[1:])
	case "start":
		return commandStart(ctx, args[1:])
	case "status":
		return commandStatus(ctx, args[1:])
	case "logs":
		return commandLogs(ctx, args[1:])
	case "enroll":
		return commandEnroll(ctx, args[1:])
	case "instance":
		return commandInstance(ctx, args[1:])
	case "test":
		return commandTest(ctx, args[1:])
	case "help", "--help", "-h":
		return emitHelp(emit, "root", helpText)
	default:
		return emit.fail("usage", "unknown command: "+args[0], "Run flow --help.", exitUsage)
	}
}

type fileDescriptor interface {
	Fd() uintptr
}

func interactiveTerminal(input io.Reader, output io.Writer) bool {
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	in, inputOK := input.(fileDescriptor)
	out, outputOK := output.(fileDescriptor)
	return inputOK && outputOK && term.IsTerminal(in.Fd()) && term.IsTerminal(out.Fd())
}

// requestedCommandID keeps JSON failures as easy to route as successful
// envelopes without ever including instance names, remote argv or option
// values. the returned identifier describes only the fixed CLI action path.
func requestedCommandID(arguments []string) string {
	if len(arguments) == 0 {
		return "flow"
	}
	switch arguments[0] {
	case "help", "--help", "-h":
		return "help"
	case "instance-runtime":
		if len(arguments) >= 2 {
			switch arguments[1] {
			case "enroll", "reconcile", "status", "secret":
				return "instance-runtime." + arguments[1]
			}
		}
		return "instance-runtime"
	case "dashboard", "tui", "serve":
		return arguments[0]
	}
	group := arguments[0]
	if _, known := commandGroupHelpText[group]; !known {
		return "flow"
	}
	for length := min(len(arguments), 3); length >= 2; length-- {
		command := strings.Join(arguments[:length], ".")
		if _, known := commandLeafHelpGroups[command]; known {
			return command
		}
	}
	if group == "instance" && len(arguments) >= 2 {
		switch arguments[1] {
		case "hostkey", "key", "secret":
			return "instance." + arguments[1]
		}
	}
	return group
}

func emitHelp(emit *emitter, topic, text string) int {
	if emit.json {
		return emit.success("help", map[string]any{"topic": topic, "text": text}, "")
	}
	fmt.Fprint(emit.stdout, text)
	return exitOK
}

func helpTopic(arguments []string) string {
	if len(arguments) != 2 {
		return "root"
	}
	if arguments[0] == "help" {
		return arguments[1]
	}
	return arguments[0]
}

func requestedHelpTopic(arguments []string) (string, bool) {
	if len(arguments) != 2 {
		return "", false
	}
	switch {
	case arguments[0] == "help":
		return arguments[1], true
	case arguments[1] == "help" || arguments[1] == "--help" || arguments[1] == "-h":
		return arguments[0], true
	default:
		return "", false
	}
}

type globalOptions struct {
	json       bool
	help       bool
	version    bool
	home       string
	sourceRoot string
}

func parseGlobal(arguments []string) (globalOptions, []string, error) {
	var result globalOptions
	args := make([]string, 0, len(arguments))
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument == "--" {
			args = append(args, arguments[index:]...)
			break
		}
		switch {
		case argument == "--json":
			result.json = true
		case argument == "--help" || argument == "-h":
			if len(args) == 0 {
				result.help = true
			} else {
				args = append(args, argument)
			}
		case argument == "--version":
			result.version = true
		case argument == "--home":
			index++
			if index >= len(arguments) {
				return result, nil, errors.New("--home requires a path")
			}
			result.home = arguments[index]
		case strings.HasPrefix(argument, "--home="):
			result.home = strings.TrimPrefix(argument, "--home=")
		case argument == "--source-root":
			index++
			if index >= len(arguments) {
				return result, nil, errors.New("--source-root requires a path")
			}
			result.sourceRoot = arguments[index]
		case strings.HasPrefix(argument, "--source-root="):
			result.sourceRoot = strings.TrimPrefix(argument, "--source-root=")
		default:
			args = append(args, argument)
		}
	}
	if result.home != "" && !filepath.IsAbs(result.home) {
		return result, nil, errors.New("--home must be an absolute path")
	}
	if result.sourceRoot != "" && !filepath.IsAbs(result.sourceRoot) {
		return result, nil, errors.New("--source-root must be an absolute path")
	}
	return result, args, nil
}

func discoverSourceRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if info, statErr := os.Stat(filepath.Join(directory, "go.mod")); statErr == nil && info.Mode().IsRegular() {
			if profileInfo, profileErr := os.Stat(filepath.Join(directory, "profiles")); profileErr == nil && profileInfo.IsDir() {
				return directory, nil
			}
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", errors.New("Dynamicflow source root not found")
		}
		directory = parent
	}
}

func usage(ctx *commandContext, message string) int {
	return ctx.out.fail("usage", message, "Run flow --help.", exitUsage)
}

func commandGroupHelp(arguments []string) (string, bool) {
	if len(arguments) != 2 {
		return "", false
	}
	group := ""
	switch {
	case arguments[0] == "help":
		group = arguments[1]
	case arguments[1] == "help" || arguments[1] == "--help" || arguments[1] == "-h":
		group = arguments[0]
	default:
		return "", false
	}
	text, ok := commandGroupHelpText[group]
	return text, ok
}

// commandLeafHelp recognizes only complete, public command paths followed
// immediately by a help flag. keeping this allowlist ahead of operator-state
// initialization makes leaf help state-free, while unknown leaves remain
// ordinary usage errors. a help-looking remote argument after the literal
// instance-exec separator is deliberately not a local help request.
func commandLeafHelp(arguments []string) (string, string, bool) {
	if len(arguments) < 3 {
		return "", "", false
	}
	help := arguments[len(arguments)-1]
	if help != "--help" && help != "-h" {
		return "", "", false
	}
	for _, argument := range arguments[:len(arguments)-1] {
		if argument == "--" {
			return "", "", false
		}
	}
	leaf := strings.Join(arguments[:len(arguments)-1], ".")
	group, ok := commandLeafHelpGroups[leaf]
	if !ok {
		return "", "", false
	}
	text, ok := commandGroupHelpText[group]
	return leaf, text, ok
}

var commandLeafHelpGroups = map[string]string{
	"system.init":             "system",
	"system.status":           "system",
	"control.bind":            "control",
	"control.check":           "control",
	"control.install":         "control",
	"control.status":          "control",
	"serving.configure":       "serving",
	"serving.show":            "serving",
	"start.serving":           "start",
	"status.serving":          "status",
	"logs.serving":            "logs",
	"key.create":              "key",
	"key.list":                "key",
	"key.rotate":              "key",
	"key.revoke":              "key",
	"profile.list":            "profile",
	"profile.show":            "profile",
	"release.build":           "release",
	"release.verify":          "release",
	"release.publish":         "release",
	"enroll.create":           "enroll",
	"enroll.list":             "enroll",
	"enroll.revoke":           "enroll",
	"instance.list":           "instance",
	"instance.status":         "instance",
	"instance.logs":           "instance",
	"instance.apply":          "instance",
	"instance.bind":           "instance",
	"instance.hostkey.pin":    "instance",
	"instance.hostkey.rotate": "instance",
	"instance.key.finalize":   "instance",
	"instance.ssh":            "instance",
	"instance.exec":           "instance",
	"instance.revoke":         "instance",
	"instance.secret.reveal":  "instance",
	"instance.secret.rotate":  "instance",
	"test.lab":                "test",
}

var commandGroupHelpText = map[string]string{
	"system": `Usage:
	  flow system init --name NAME [--control-name NAME] [--plan]
  flow system status

Create or resume a provider-independent system and its first Control bootstrap.
Only the public bootstrap key is returned; VM host trust must be confirmed out
of band before connectivity is attempted.
`,
	"control": `Usage:
  flow control bind NAME --host HOST --ssh-user USER
      --os debian-13|ubuntu-24.04 --hostkey-file ABS
      --evidence provider-console|provider-attestation
      [--ssh-port PORT] [--plan]
  flow control check NAME [--plan]
  flow control install NAME [--plan]
  flow control status

Bind records only independently verified local host trust and performs no
network connection. Check performs exactly one direct attempt over the pinned
route with fixed /bin/true and has no retry, fallback or arbitrary command.
Install prepares a signed generation-1 route-free local checkpoint with zero
network connections. It does not install the remote node and never marks
Control ready. --plan validates and previews without changing state.
`,
	"init": `Usage:
  flow init

Initialize private operator state and three independent signing roots idempotently.
`,
	"doctor": `Usage:
  flow doctor

Validate tools, permissions, profiles, signing roots and key separation.
`,
	"serving": `Usage:
  flow serving configure --url https://HOST:PORT --ca-file ABS --tls-pin SHA256:BASE64
  flow serving show

Show is local and read-only. Configure is currently fail-closed with
control_route_unavailable until its signed via-Control transport is available;
it never falls back to direct operator-to-serving HTTPS.
`,
	"start": `Usage:
  flow start serving [--plan] --public-url https://HOST:PORT
      [--listen HOST:PORT] [--state-root ABS] [--release-root ABS]
      [--release-public-key ABS --desired-public-key ABS --control-public-key ABS]
      [--service-user USER]

The public operator command, including --plan, is currently fail-closed with
control_route_unavailable until serving reconciliation is routed through Control.
`,
	"status": `Usage:
  flow status serving

Currently fail-closed with control_route_unavailable until status is routed
through Control.
`,
	"logs": `Usage:
  flow logs serving [--lines N]

Currently fail-closed with control_route_unavailable until bounded journal
access is routed through Control.
`,
	"key": `Usage:
  flow key create --name NAME [--scope operator|instance]
  flow key list [--scope operator|instance]
  flow key rotate --name NAME [--scope operator|instance]
  flow key revoke --name NAME [--scope operator|instance]
`,
	"profile": `Usage:
  flow profile list [--internal]
  flow profile show NAME
`,
	"release": `Usage:
  flow release build [--rebuild] [--generation N]
  flow release verify [ABSOLUTE-STAGE]
  flow release publish [--remote | --root ABSOLUTE-PATH] [--plan]

Build and verify are local. Publish is local only with an explicit absolute
non-root --root. --remote and an omitted destination, including --plan, fail
closed until signed via-Control publication is available.
`,
	"enroll": `Usage:
  flow enroll create --name NAME --profile PROFILE
      [--host HOST --ssh-user USER [--ssh-port PORT]]
      [--key OPERATOR-KEY] [--ttl DURATION]
  flow enroll list
  flow enroll revoke (--id ID | --name NAME)

Create, list and revoke currently fail closed before HTTP until their signed
via-Control transport is available. They never use a direct serving fallback.
`,
	"instance": `Usage:
  flow instance list
  flow instance status NAME
  flow instance logs NAME [--component COMPONENT]
  flow instance apply NAME --profile PROFILE [--plan]
  flow instance bind NAME --host HOST --ssh-user USER [--ssh-port PORT]
  flow instance hostkey pin NAME --public-key-file PATH
  flow instance hostkey rotate NAME --public-key-file PATH
  flow instance key finalize NAME [--plan]
  flow instance ssh NAME [--gui] [--local-port PORT]
  flow instance exec NAME -- COMMAND [ARG...]
  flow instance revoke NAME
  flow instance secret reveal NAME --secret vnc
  flow instance secret rotate NAME --secret vnc

List, bind and provider-console hostkey pin/rotate are local. Status, logs,
apply, revoke, SSH/GUI, exec, VNC secret operations and key finalize (including
their plan modes) currently fail closed until signed via-Control routes exist.
`,
	"test": `Usage:
  flow test lab [--inventory ABSOLUTE-PATH] [--plan]

--plan is local and read-only. A real run currently fails closed until every
remote lab action is implemented over verified Control routes.
`,
}

const helpText = `Dynamicflow operator CLI

Usage:
  flow                              Open the resumable terminal UI on a TTY
  flow [--json] [--home PATH] <command> [options]

Core:
	  flow system init --name NAME      Create/resume a system and first Control key; --plan previews
  flow system status                Show active system, Control gate and tasks
  flow control bind NAME --host HOST --ssh-user USER --os OS --hostkey-file ABS --evidence SOURCE [--plan]
                                     Pin the first Control endpoint and OOB-verified Ed25519 host key
  flow control check NAME [--plan]  Run one direct pinned /bin/true connectivity check; no retry or fallback
  flow control install NAME [--plan]
                                     Prepare the local signed route-free install checkpoint; 0 network, not ready
  flow control status               Show the active system's Control binding, task and topology
  flow dashboard                    Print the noninteractive dashboard snapshot
  flow init                         Initialize private operator state and trust roots
  flow doctor                       Validate tools, permissions, profiles and trust roots
  flow start serving [--plan]       Reconcile the local serving role idempotently
    First start: --public-url URL; optional --listen, --state-root, --release-root, --service-user
    and explicit --release-public-key/--desired-public-key/--control-public-key
  flow status serving               Show serving process and release state
  flow logs serving                 Read sanitized serving logs
  flow serving configure --url URL --ca-file PATH --tls-pin PIN
                                     Pin the operator to a serving node
  flow serving show                 Show the pinned serving trust binding

Keys:
  flow key create --name NAME       Create a local Ed25519 operator key
  flow key list                     List public key metadata
  flow key rotate --name NAME       Create and activate the next key generation
  flow key revoke --name NAME       Revoke without deleting audit evidence

Profiles and releases:
  flow profile list
  flow profile show NAME
  flow release build [--rebuild]
  flow release verify [PATH]
  flow release publish [--remote | --root PATH] [--plan]

Enrollment and instances:
  flow enroll create --name NAME --profile PROFILE
                                     Optional: --host/--ssh-user/--ssh-port, --key, --ttl
  flow enroll list
  flow enroll revoke (--id ID | --name NAME)
  flow instance list
  flow instance status NAME
  flow instance logs NAME [--component COMPONENT]
  flow instance apply NAME --profile PROFILE [--plan]
  flow instance bind NAME --host HOST --ssh-user USER [--ssh-port PORT]
  flow instance hostkey pin NAME --public-key-file PATH
  flow instance hostkey rotate NAME --public-key-file PATH
  flow instance key finalize NAME [--plan]
                                     Prove the new key over pinned SSH, then remove the old key
  flow instance ssh NAME [--gui] [--local-port PORT]
  flow instance exec NAME -- COMMAND [ARG...]
  flow instance revoke NAME
  flow instance secret reveal NAME --secret vnc
  flow instance secret rotate NAME --secret vnc

Lab:
  flow test lab [--inventory .flow/lab.yaml] [--plan]

Current Control-route gate:
  Local operations remain available: system/control/dashboard/init/doctor,
  key/profile, release build/verify, explicit local release publish --root,
  instance list/bind/hostkey and test lab --plan.
  Serving configure/start/status/logs, enrollment lifecycle, remote or implicit
  release publish, non-plan lab execution, and instance status/logs/apply/
  revoke/SSH/GUI/exec/VNC/key-finalize return control_route_unavailable before
  operator state, network or child-process access. There is no environment,
  stored-state or automatic direct fallback.

Global options:
  --json             Emit one stable JSON result instead of human text
  --home PATH        Private state root (default: FLOW_HOME or XDG state)
  --source-root PATH Repository root used for profiles and release builds
  --version          Print CLI version

Global options are recognized anywhere before a literal -- separator. After --,
all arguments belong to the explicitly requested remote command.

Secrets are read from TTY/stdin or private files, never accepted as command-line
values. Help remains available for gated commands so automation can discover
their contract, but invoking them cannot reach the retired direct transports.

The one-time enroll create result and explicit instance secret reveal/rotate
result deliberately contain the requested credential in stdout/JSON. Do not
capture either result in shell history, CI logs or persistent automation output.
`
