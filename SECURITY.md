# Security policy

## Support status

Development snapshot; no version is supported for production use.

## Reporting a vulnerability

When available, use GitHub's private vulnerability reporting under the
repository's **Security** tab. If that channel is unavailable, open an issue
requesting a private reporting channel, without describing the vulnerability.
Private reviewers may use their existing agreed contact channel.

Do not post private keys, FLOW_HOME state, host inventories or release state in public issues.
Include the affected commit and component, the trust boundary involved,
expected behavior and a minimal reproduction with synthetic inputs in the
private report. There is no guaranteed response time or security support SLA.

## Evaluation boundaries

Use operator-owned disposable VMs for integration tests. Keep the unfinished
control route disabled; core checks do not qualify a multi-VM deployment.
