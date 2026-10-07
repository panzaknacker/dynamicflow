// Package tui implements Dynamicflow's terminal operator surface. It calls
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
	operationContext, cancel := context.WithCancel(ctx)
	defer cancel()
	model := newModel(operationContext, app, snapshot, environment)
	var program *tea.Program
	model.send = func(message tea.Msg) { program.Send(message) }
	program = tea.NewProgram(model,
		// Cancelling Bubble Tea's own context kills pending commands before
		// their durable cleanup can complete. Model.Init observes our operation
		// context and requests a drain instead.
		tea.WithFilter(shutdownFilter),
		tea.WithInput(input),
		tea.WithOutput(output),
		tea.WithEnvironment(environment),
		tea.WithFPS(30),
	)
	_, err = program.Run()
	if err == nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
