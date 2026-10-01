# Local review — 2026-10-01

`make check demo` passed with Go 1.26.8: build, 32 unit-test packages,
the same packages with the race detector, vet, static checks and all five demo
steps. No runtime implementation or tests were changed.

[Complete output](verification/2026-10-01-core-go1.26.8.txt).

An initial run inside the agent sandbox failed because loopback sockets were
blocked and root directory ownership appeared as UID/GID 65534. The unchanged
source passed outside that sandbox, in a checkout with trusted ancestor paths.

## Environment and source

Fedora 44 x86_64, kernel 7.2.5-200.fc44; Go 1.26.8 where used and Python
3.14.7. Prepared tools and module caches were reused; Go proxy and checksum
lookups were disabled. Data and keys were synthetic and temporary.

[Context](verification/2026-10-01-context.json) ·
[Code and build inputs](verification/2026-10-01-inputs.sha256)

Local checkout paths, tool paths and temporary demo key values were normalized; results were not
changed. Repository history was scanned with Gitleaks 8.30.1 across all refs
without reported findings. This does not audit development history absent
from the snapshot or qualify a production deployment.

[Hosted CI start failures](HOSTED-CI.md) are separate from these local results.
