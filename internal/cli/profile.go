package cli

import (
	"fmt"
	"strings"

	"dynamicflow/internal/profiles"
)

func loadProfiles(ctx *commandContext) (*profiles.Registry, error) {
	if ctx.profiles == "" {
		return nil, fmt.Errorf("profile directory not found; set --source-root or FLOW_PROFILES_DIR")
	}
	return profiles.LoadDir(ctx.profiles)
}

func commandProfile(ctx *commandContext, args []string) int {
	if len(args) == 0 {
		return usage(ctx, "usage: flow profile <list|show>")
	}
	registry, err := loadProfiles(ctx)
	if err != nil {
		return ctx.out.fail("profile", err.Error(), "Repair the declarative profile directory.", exitConfig)
	}
	switch args[0] {
	case "list":
		flags := newCommandFlagSet(ctx, "profile list")
		includeInternal := flags.Bool("internal", false, "show internal dependency profiles")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return usage(ctx, "usage: flow profile list [--internal]")
		}
		items := registry.List(*includeInternal)
		if !ctx.out.json {
			for _, profile := range items {
				availability := "declarative-only"
				if profile.Installable {
					availability = "installable"
				}
				fmt.Fprintf(ctx.out.stdout, "%-16s %-16s %s\n", profile.Name, availability, profile.Description)
			}
			return exitOK
		}
		return ctx.out.success("profile.list", items, "")
	case "show":
		flags := newCommandFlagSet(ctx, "profile show")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 1 {
			return usage(ctx, "usage: flow profile show NAME")
		}
		name := flags.Arg(0)
		profile, exists := registry.Get(name)
		if !exists {
			return ctx.out.fail("profile_not_found", "unknown profile: "+name, "Run flow profile list.", exitConfig)
		}
		resolved, err := registry.Resolve(name)
		if err != nil {
			return ctx.out.fail("profile", err.Error(), "Fix the profile graph.", exitConflict)
		}
		order := make([]string, len(resolved))
		components := []string{}
		seen := map[string]bool{}
		for index, dependency := range resolved {
			order[index] = dependency.Name
			for _, component := range dependency.Components {
				if !seen[component] {
					components = append(components, component)
					seen[component] = true
				}
			}
		}
		data := map[string]any{"profile": profile, "order": order, "components": components}
		human := fmt.Sprintf("%s\nDependency order: %s\nArtifacts: %s", profile.Description, strings.Join(order, " -> "), strings.Join(components, ", "))
		return ctx.out.success("profile.show", data, human)
	default:
		return usage(ctx, "unknown profile command: "+args[0])
	}
}
