package cli

import (
	"errors"
	"flag"
	"regexp"

	"dynamicflow/internal/application"
)

var expectedControlSystemID = regexp.MustCompile(`^sys-[0-9a-f]{32}$`)

// Separate CLI invocations cannot retain a TUI confirmation's in-memory
// system binding. Scripts can carry the plan's immutable system_id explicitly;
// the shared application services then reject a changed active context.
func registerControlSystemExpectation(flags *flag.FlagSet) *application.RequestMeta {
	meta := &application.RequestMeta{Surface: application.SurfaceCLI}
	flags.Func("expect-system", "require the exact system ID from the confirmed plan", func(value string) error {
		if !expectedControlSystemID.MatchString(value) {
			return errors.New("expected a complete sys- ID with 32 lowercase hexadecimal digits")
		}
		meta.ExpectedSystemID = value
		return nil
	})
	return meta
}
