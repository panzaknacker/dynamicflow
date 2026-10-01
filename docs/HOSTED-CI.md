# Hosted CI status

## 2026-10-01

GitHub Actions were disabled before this review. The existing verification and
secret-scan workflows were temporarily enabled and dispatched:

- [Verification run](https://github.com/panzaknacker/dynamicflow/actions/runs/36853153233)
- [Secret-scan run](https://github.com/panzaknacker/dynamicflow/actions/runs/36853165889)

Both ended with `startup_failure` before any job was created. The Jobs API and
check-run list were empty; no runner logs or error annotations were available.
The API did not expose the underlying startup reason. No tests executed in
these hosted runs, and they do not establish a passing CI result.

Actionlint 1.7.12 independently accepted both workflow files. The pinned
checkout action exists. These checks do not diagnose the GitHub startup failure.

Actions were returned to their original disabled state to avoid repeated
notifications during documentation changes. The failed runs remain available.
Re-enable and observe the workflows once the startup issue is understood;
do not infer production readiness from a later local or hosted green result.

[Repository status](../PROJECT_STATUS.md)
