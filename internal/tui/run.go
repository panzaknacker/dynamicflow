// package tui implements dynamicflow's terminal operator surface. it calls
// application services directly and never shells out to the CLI.
package tui

import (
	"context"
	"errors"
	"io"

	tea "charm.land/bubbletea/v2"

	"dynamicflow/internal/application"
)

func Run(ctx context.Context, app *application.Application, input io.Reader, output io.Writer, environment []string) error {
	if app == nil || input == nil || output == nil {
		return errors.New("TUI requires an application and terminal input/output")
	}
	snapshot, err := app.Dashboard(ctx)
	if err != nil {
		return err
	}
	model := newModel(ctx, app, snapshot, environment)
	program := tea.NewProgram(model,
		tea.WithContext(ctx),
		tea.WithInput(input),
		tea.WithOutput(output),
		tea.WithEnvironment(environment),
		tea.WithFPS(30),
	)
	_, err = program.Run()
	return err
}
