package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type emitter struct {
	json   bool
	stdout io.Writer
	stderr io.Writer
	// command is the normalized requested command used for failure envelopes.
	// success and failData callers pass their more specific command directly.
	command string
}

func (e *emitter) success(command string, data any, human string) int {
	if e.json {
		_ = json.NewEncoder(e.stdout).Encode(map[string]any{
			"ok": true, "command": command, "data": data,
		})
	} else if human != "" {
		fmt.Fprintln(e.stdout, human)
	}
	return exitOK
}

func (e *emitter) failData(command string, data any, code, message, next string, status int) int {
	if !e.json {
		return e.fail(code, message, next, status)
	}
	_ = json.NewEncoder(e.stderr).Encode(map[string]any{
		"ok":      false,
		"command": command,
		"data":    data,
		"error": map[string]any{
			"code": code, "message": message, "next": next,
		},
	})
	return status
}

func (e *emitter) fail(code, message, next string, status int) int {
	if e.json {
		command := e.command
		if command == "" {
			command = "flow"
		}
		_ = json.NewEncoder(e.stderr).Encode(map[string]any{
			"ok":      false,
			"command": command,
			"error":   map[string]any{"code": code, "message": message, "next": next},
		})
	} else {
		fmt.Fprintf(e.stderr, "ERROR [%s]: %s\n", code, message)
		if next != "" {
			fmt.Fprintf(e.stderr, "Next: %s\n", next)
		}
	}
	return status
}

func (e *emitter) phase(name, status, detail string) {
	if e.json {
		return
	}
	if detail == "" {
		fmt.Fprintf(e.stderr, "[%s] %s\n", name, status)
		return
	}
	fmt.Fprintf(e.stderr, "[%s] %s: %s\n", name, status, detail)
}

type auditEvent struct {
	Time    time.Time      `json:"time"`
	Action  string         `json:"action"`
	Outcome string         `json:"outcome"`
	Fields  map[string]any `json:"fields,omitempty"`
}

func audit(ctx *commandContext, action, outcome string, fields map[string]any) error {
	return ctx.store.AppendJSONL("logs/audit.jsonl", auditEvent{
		Time: time.Now().UTC(), Action: action, Outcome: outcome, Fields: fields,
	})
}
