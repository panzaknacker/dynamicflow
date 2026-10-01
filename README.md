# dynamicflow

Reusable Linux VM profiles for research environments and authorized security labs.
The Go control plane resolves component dependencies, verifies signed releases
and manages desired instance state.

I started dynamicflow to avoid rebuilding similar VM and node configurations
when switching hosting providers. Private variants have been used for my own
research; their exact relationship to this snapshot is still being documented.
[Background and decisions](docs/PORTFOLIO.md).

**In development.** The local Go core is available for evaluation. Remote
lifecycle operations, enrollment and serving remain disabled with
`control_route_unavailable` while the replacement control route is incomplete.
[Scope and remaining work](PROJECT_STATUS.md).

## Try the local walkthrough

Requirements: Linux, Bash, GNU Make, OpenSSH (`ssh`, `ssh-keygen`) and the Go
version specified in [go.mod](go.mod). Initial builds may download Go modules.

```sh
make demo
```

The walkthrough builds the CLI, creates temporary state, resolves profiles,
verifies signatures and demonstrates the expected rejection of remote actions.
It needs no cloud account or deployed VM. [Steps and troubleshooting](docs/DEMO.md).

For the complete local core check, also install a C compiler:

```sh
make check
```

This runs the build, unit and race tests, `go vet` and static security checks.
VNC path tests require a checkout whose ancestor directories are not group- or
world-writable; a checkout under `/tmp` does not satisfy that condition.

## What to review

| Area | Code entry | Decision |
| --- | --- | --- |
| Profiles | [Resolution](internal/cli/profile.go) · [Definitions](profiles/) | Resolve dependencies before changing an environment. |
| Signatures | [Signing](internal/signing/) · [Verification](internal/release/) | Release, desired-state and control signatures use separate trust roots. |
| Remote boundary | [Control-route gate](internal/cli/control_route_gate.go) | Unfinished operations fail before state, network or process access. |
| Release serving | [Serving component](serving/) | Distribution and a complete deployment have separate qualification requirements. |

`examstation` is declared but its source is absent; `decepticon` is an external
integration. Neither is enabled in the target runner. Component checks and a
complete platform release are separate from `make check`.

## Evidence and limits

The recorded September 2026 local runs passed the demo and full core check with
Go 1.24.2 and 1.26.8, including 32 test packages with and without the race
detector. [Commands, logs and environment](docs/VERIFICATION.md).
[Current GitHub workflows](https://github.com/panzaknacker/dynamicflow/actions)
are separate from these local results.
[Hosted startup failure and current CI state](docs/HOSTED-CI.md).

`FLOW_HOME` holds private keys, trust pins and audit data and stays outside Git.
SSH host keys need independent verification; `ssh-keyscan` alone does not
establish trust. VNC remains bound to loopback. There is no supported production
release; the control route, multi-VM lifecycle and recovery still need qualification.
[Threat model](docs/THREAT-MODEL.md).

[Latest local review and logs](docs/LOCAL-REVIEW-2026-10-01.md).

## Documentation

- [Demo](docs/DEMO.md) · [Verification](docs/VERIFICATION.md) · [Project status](PROJECT_STATUS.md)
- [Development](docs/DEVELOPMENT.md) · [Architecture](docs/adr/0001-platform-control-plane.md)
- [Operator runbook](docs/OPERATOR-RUNBOOK.md) · [Recovery](docs/RECOVERY-RUNBOOK.md)
- [Qualification matrix](docs/COMPLETION-AUDIT.md) · [VM lab](docs/LAB-E2E-RUNBOOK.md)
- [Contributing](CONTRIBUTING.md) · [Security reports](SECURITY.md)

Detailed engineering notes and historical evidence include German documents.

## License

[Apache License 2.0](LICENSE). Preserve the notices for third-party components.
