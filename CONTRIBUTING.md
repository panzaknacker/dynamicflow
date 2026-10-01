# Contributing

Start with [Development guide](docs/DEVELOPMENT.md) and [PROJECT_STATUS.md](PROJECT_STATUS.md).
Keep changes focused and explain the problem, resulting behavior and affected
trust boundaries.

## Local validation

Run `make check` for core changes and `make demo` for the local walkthrough.
Prepare Linux, Go from `go.mod`, GNU Make, Bash, OpenSSH and a C compiler.
The VNC checks require a checkout outside group- or world-writable ancestors.

Run the relevant checks before submitting a change and record their actual
results, environment and skipped checks. Format Go changes with `gofmt`.
Behavior changes need regression coverage for rejected inputs and failure
paths as well as the intended workflow.

## Review expectations

Preserve explicit approvals, pinned trust, failure handling and recovery
boundaries. Update the component status when a capability or its qualification
changes. Distinguish local, simulated and deployed results.

Use synthetic fixtures. Do not commit generated binaries, private state,
credentials, real inventories or copied third-party code without its notices.
Report sensitive findings through [SECURITY.md](SECURITY.md).

## Source terms

Contributions follow the existing [Apache-2.0 license](LICENSE).
