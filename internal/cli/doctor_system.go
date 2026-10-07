package cli

import (
	"context"
	"fmt"
	"strings"

	"dynamicflow/internal/application"
)

func doctorSystem(ctx *commandContext) (int, bool) {
	result, err := application.DiagnoseLocal(context.Background(), application.Config{Store: ctx.store})
	if err != nil {
		return emitApplicationError(ctx, err), true
	}
	if result.Scope == "operator" {
		return 0, false
	}
	if !ctx.out.json {
		fmt.Fprintln(ctx.out.stdout, "Local diagnostics for the active Dynamicflow system")
		if result.SystemID != "" {
			fmt.Fprintln(ctx.out.stdout, "System:", result.SystemID)
		}
		for _, check := range result.Checks {
			fmt.Fprintf(ctx.out.stdout, "%-7s %-24s %s\n", strings.ToUpper(string(check.Status)), check.Name, check.Detail)
			if check.Next != "" {
				fmt.Fprintln(ctx.out.stdout, "        Next:", check.Next)
			}
		}
		ready := "no"
		if result.ControlReady {
			ready = "yes"
		}
		fmt.Fprintf(ctx.out.stdout, "Control ready: %s\nNetwork connections: 0; remote availability was not checked.\n", ready)
	}
	if !result.Healthy {
		return ctx.out.failData("doctor", result, "doctor_failed", "One or more local system checks failed.", "Resolve the failed checks while preserving the existing trust identities.", exitConfig), true
	}
	return ctx.out.success("doctor", result, "Local checks passed."), true
}
