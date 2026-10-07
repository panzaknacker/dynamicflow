package cli

import (
	"flag"
	"io"
	"path/filepath"
)

const (
	controlRouteUnavailableCode = "control_route_unavailable"
	controlRouteUnavailableText = "the requested operator action has no verified via-Control route; direct serving and instance access is disabled"
	controlRouteUnavailableNext = "Complete and select a verified Control route with flow control status; retry only after this action has a signed via-Control implementation."
)

// operatorActionNeedsControlRoute is the temporary public-surface enforcement
// boundary while the corresponding signed via-Control transports are being
// implemented. It deliberately depends only on argv: operator state,
// environment variables and legacy endpoint configuration cannot enable a
// direct fallback.
//
// Raw serving/instance/control runtime entry points are dispatched before this
// gate and are not operator lifecycle commands. The first Control bootstrap
// remains available through the dedicated control command group.
func operatorActionNeedsControlRoute(arguments []string) bool {
	if len(arguments) < 2 {
		return false
	}
	switch arguments[0] {
	case "serving":
		return arguments[1] == "configure"
	case "start", "status", "logs":
		return arguments[1] == "serving"
	case "enroll":
		switch arguments[1] {
		case "create", "list", "revoke":
			return true
		}
	case "instance":
		switch arguments[1] {
		case "status", "logs", "apply", "ssh", "exec", "revoke", "secret":
			return true
		case "key":
			return len(arguments) >= 3 && arguments[2] == "finalize"
		}
	case "release":
		// Publishing is local only when the caller supplies an unambiguous,
		// absolute, non-root destination. An omitted destination historically
		// selected remote serving from mutable local state, so ambiguity must
		// fail closed. This includes remote --plan.
		return arguments[1] == "publish" && !explicitLocalReleasePublish(arguments[2:])
	case "test":
		// The lab plan parses private local inventory and pinned metadata only.
		// Every non-plan lab invocation can start SSH and is therefore gated.
		return arguments[1] == "lab" && !explicitReadOnlyPlan(arguments[2:])
	}
	return false
}

func explicitLocalReleasePublish(arguments []string) bool {
	set := flag.NewFlagSet("release publish route classification", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	root := set.String("root", "", "")
	remote := set.Bool("remote", false, "")
	_ = set.Bool("plan", false, "")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 || *remote {
		return false
	}
	return filepath.IsAbs(*root) && filepath.Clean(*root) != string(filepath.Separator)
}

func explicitReadOnlyPlan(arguments []string) bool {
	set := flag.NewFlagSet("read-only plan classification", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	_ = set.String("inventory", "", "")
	plan := set.Bool("plan", false, "")
	return set.Parse(arguments) == nil && set.NArg() == 0 && *plan
}
