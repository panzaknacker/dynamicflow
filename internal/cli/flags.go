package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

// newCommandFlagSet keeps flag package diagnostics out of JSON output. the
// caller emits the one structured usage error after parsing fails.
func newCommandFlagSet(ctx *commandContext, name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	if ctx.out.json {
		set.SetOutput(io.Discard)
	} else {
		set.SetOutput(ctx.out.stderr)
	}
	return set
}

// parseInterspersed allows documented options on either side of positional
// operands. the standard flag package stops at the first operand, which makes
// natural commands such as `instance ssh NAME --gui` fail unexpectedly.
// a literal -- ends option parsing and duplicate options are rejected instead
// of relying on ambiguous last-value-wins behavior.
func parseInterspersed(set *flag.FlagSet, arguments []string) error {
	normalized, err := normalizeInterspersed(set, arguments)
	if err != nil {
		fmt.Fprintln(set.Output(), err)
		return err
	}
	return set.Parse(normalized)
}

func normalizeInterspersed(set *flag.FlagSet, arguments []string) ([]string, error) {
	options := make([]string, 0, len(arguments))
	operands := make([]string, 0, len(arguments))
	seen := make(map[string]struct{})
	optionsEnded := false

	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if optionsEnded {
			operands = append(operands, argument)
			continue
		}
		if argument == "--" {
			optionsEnded = true
			continue
		}
		name, hasInlineValue, isOption, err := optionName(argument)
		if err != nil {
			return nil, err
		}
		if !isOption {
			operands = append(operands, argument)
			continue
		}

		definition := set.Lookup(name)
		if definition == nil {
			// preserve flag's conventional help behavior.
			if name == "h" || name == "help" {
				options = append(options, argument)
				continue
			}
			return nil, fmt.Errorf("flag provided but not defined: --%s", name)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("flag provided more than once: --%s", name)
		}
		seen[name] = struct{}{}
		options = append(options, argument)
		if hasInlineValue || isBooleanFlag(definition) {
			continue
		}
		index++
		if index >= len(arguments) {
			return nil, fmt.Errorf("flag needs an argument: --%s", name)
		}
		options = append(options, arguments[index])
	}

	// the inserted separator ensures operands beginning with '-' stay operands
	// after options have been moved in front of them.
	normalized := append(options, "--")
	return append(normalized, operands...), nil
}

func optionName(argument string) (name string, hasInlineValue bool, isOption bool, err error) {
	if argument == "-" || !strings.HasPrefix(argument, "-") {
		return "", false, false, nil
	}
	raw := strings.TrimPrefix(argument, "-")
	raw = strings.TrimPrefix(raw, "-")
	if raw == "" {
		return "", false, false, fmt.Errorf("invalid empty flag")
	}
	name, _, hasInlineValue = strings.Cut(raw, "=")
	if name == "" {
		return "", false, false, fmt.Errorf("invalid empty flag")
	}
	return name, hasInlineValue, true, nil
}

func isBooleanFlag(definition *flag.Flag) bool {
	boolean, ok := definition.Value.(interface{ IsBoolFlag() bool })
	return ok && boolean.IsBoolFlag()
}
