#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$repo_root"

fail() {
    printf 'static-security: %s\n' "$*" >&2
    exit 1
}

static_tmp="$(mktemp -d "${TMPDIR:-/tmp}/dynamicflow-static.XXXXXXXX")"
cleanup() {
    case "$static_tmp" in
    "${TMPDIR:-/tmp}"/dynamicflow-static.*) rm -rf -- "$static_tmp" ;;
    *) printf 'static-security: refusing unsafe temporary cleanup: %s\n' "$static_tmp" >&2 ;;
    esac
}
trap cleanup EXIT HUP INT TERM

# source archives and pre-commit copies are supported. never discover a parent
# repository: its index and ignore rules are not the publication boundary.
git_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ "$git_root" == "$repo_root" ]]; then
    mapfile -d '' platform_files < <(
        git ls-files --cached --others --exclude-standard -z -- \
            cmd internal profiles tests ssh vpn pbp serving examstation \
            'decepticon/*.sh' decepticon/VERSION Makefile go.mod README.md .gitignore
    )
else
    mapfile -d '' platform_files < <(
        find cmd internal profiles tests ssh vpn pbp serving decepticon \
            \( -type d \( -name .git -o -name __pycache__ -o -name .pytest_cache \
            -o -name .venv -o -name node_modules -o -name vendor -o -name dist \
            -o -name releases -o -name sets -o -name sources -o -name release \
            -o -name Decepticon -o -name dipper-staging \) \) -prune \
            -o -type f -print0
        printf '%s\0' Makefile go.mod README.md .gitignore
    )
fi
if ((${#platform_files[@]} == 0)); then
    fail 'no platform files found'
fi

private_key_re='-{5}BEGIN[[:space:]]+(OPENSSH[[:space:]]+|RSA[[:space:]]+|EC[[:space:]]+|DSA[[:space:]]+)?PRIVATE[[:space:]]+KEY-{5}'
for file in "${platform_files[@]}"; do
    [[ -f "$file" ]] || continue
    if LC_ALL=C grep -IEn -- "$private_key_re" "$file" >/dev/null; then
        LC_ALL=C grep -IEn -- "$private_key_re" "$file" >&2 || true
        fail "private-key marker found in platform file: $file"
    fi
done

tracked_secret_files=()
if [[ "$git_root" == "$repo_root" ]]; then
    mapfile -d '' tracked_secret_files < <(
        git ls-files -z -- '*.pem' '*.p12' '*.pfx' '*.key' '*id_ed25519*' '*known_hosts*'
    )
else
    for file in "${platform_files[@]}"; do
        case "$file" in
        *.pem | *.p12 | *.pfx | *.key | *id_ed25519* | *known_hosts*) tracked_secret_files+=("$file") ;;
        esac
    done
fi
if ((${#tracked_secret_files[@]} != 0)); then
    printf '%s\n' "${tracked_secret_files[@]}" >&2
    fail 'private key or host-trust file is included in publication sources'
fi

flow_bin="${FLOW_BIN:-}"
if [[ -z "$flow_bin" || ! -x "$flow_bin" ]]; then
    flow_bin="$static_tmp/flow"
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$flow_bin" ./cmd/flow
fi

help_output="$($flow_bin --help)"
required_help=(
    'flow init'
    'flow doctor'
    'flow start serving [--plan]'
    'flow status serving'
    'flow logs serving'
    'flow key create --name NAME'
    'flow key rotate --name NAME'
    'flow profile show NAME'
    'flow release build [--rebuild]'
    'flow release verify [PATH]'
    'flow release publish [--remote | --root PATH] [--plan]'
    'flow enroll create --name NAME --profile PROFILE'
    'flow instance logs NAME [--component COMPONENT]'
    'flow instance apply NAME --profile PROFILE [--plan]'
    'flow instance hostkey pin NAME --public-key-file PATH'
    'flow instance hostkey rotate NAME --public-key-file PATH'
    'flow instance ssh NAME [--gui] [--local-port PORT]'
    'flow instance exec NAME -- COMMAND [ARG...]'
    'flow instance revoke NAME'
    'flow instance secret reveal NAME --secret vnc'
    'flow instance secret rotate NAME --secret vnc'
    'flow test lab [--inventory .flow/lab.yaml] [--plan]'
)
for contract in "${required_help[@]}"; do
    [[ "$help_output" == *"$contract"* ]] || fail "help contract missing: $contract"
done
[[ "$help_output" == *'Global options are recognized anywhere before a literal -- separator.'* ]] ||
    fail 'global option/remote-command separator semantics are missing from help'
[[ "$help_output" != *'flow instance-runtime'* ]] || fail 'internal runtime leaked into operator help'
[[ "$help_output" != *'flow serve '* ]] || fail 'internal serving runtime leaked into operator help'

extract_function() {
    local file="$1"
    local function_name="$2"
    awk -v wanted="$function_name" '
    $0 ~ "^func " wanted "\\(" { active = 1 }
    active && $0 ~ "^func " && $0 !~ "^func " wanted "\\(" { exit }
    active { print }
  ' "$file"
}

# these normal lifecycle paths must never initiate SSH. instance lifecycle
# paths additionally remain outbound-HTTPS/local-state only; serving status
# and logs may invoke the fixed local systemctl/journalctl utilities.
readonly_paths=(
    'internal/cli/serving.go:commandStatus'
    'internal/cli/serving.go:commandLogs'
    'internal/cli/instance_https.go:instanceHTTPSLifecycle'
    'internal/cli/instance_https.go:instanceRevokeHTTPS'
)
for specification in "${readonly_paths[@]}"; do
    file="${specification%%:*}"
    function_name="${specification##*:}"
    body="$(extract_function "$file" "$function_name")"
    [[ -n "$body" ]] || fail "cannot locate lifecycle function $function_name"
    if grep -Eq '[.]SSHArgs[(]|instance(SSH|Exec|Secret)[(]' <<<"$body"; then
        fail "hidden SSH-capable call in normal lifecycle function $function_name"
    fi
    if grep -Fq '"ssh"' <<<"$body"; then
        fail "literal ssh execution in normal lifecycle function $function_name"
    fi
    case "$function_name" in
    instanceHTTPSLifecycle | instanceRevokeHTTPS)
        if grep -Eq 'exec[.]Command(Context)?[(]' <<<"$body"; then
            fail "process execution in outbound-HTTPS lifecycle function $function_name"
        fi
        ;;
    esac
done

# the production serving process is a passive HTTPS listener. keep every
# outbound connection and child-process primitive out of the packages linked
# into that role; explicit operator SSH and the fixed lab runner live elsewhere.
serving_process_sources=()
while IFS= read -r -d '' file; do
    serving_process_sources+=("$file")
done < <(find internal/serving internal/servingruntime -maxdepth 1 -type f -name '*.go' ! -name '*_test.go' -print0)
if ((${#serving_process_sources[@]} == 0)); then
    fail 'production serving process sources are missing'
fi
if grep -En '"os/exec"|exec[.]Command(Context)?[(]|net[.]Dial(Timeout)?[(]|[.]DialContext[(]|ssh[.]Dial[(]|ssh[.]NewClient[(]' "${serving_process_sources[@]}" >/dev/null; then
    fail 'production serving process gained an outbound dial or child-process primitive'
fi

status_body="$(extract_function internal/cli/instance_https.go instanceStatusHTTPS)"
[[ -n "$status_body" ]] || fail 'cannot locate instanceStatusHTTPS'
if grep -Fq 'instanceManager(ctx).Put' <<<"$status_body"; then
    fail 'instance status silently trusts a first SSH host key reported by serving'
fi
[[ "$status_body" == *'hostkey pin'* ]] || fail 'instance status does not direct the operator to out-of-band initial host-key pinning'

grep -Fq 'case "status", "logs", "apply":' internal/cli/instance.go ||
    fail 'status/logs/apply are no longer routed through the HTTPS-only lifecycle handler'
grep -Fq 'return instanceHTTPSLifecycle(ctx, args)' internal/cli/instance.go ||
    fail 'HTTPS-only instance lifecycle route is missing'
if grep -Fq 'logs_unavailable", "instance log upload is not enabled yet' internal/cli/instance_https.go; then
    fail 'instance logs still uses the pre-upload placeholder'
fi

# the destructive four-VM command is an explicit operator action, but its SSH
# side is a closed enum of audited scripts. the qualifying PBP policy cannot be
# shortened or have the real VPN failure silently disabled.
grep -Fq 'executor.sshArgs(host.Name)' internal/cli/lab_remote.go ||
    fail 'lab runner no longer uses the locally rotation-bound pinned SSH resolver'
grep -Fq -- '--duration-seconds 1800 --normal-cycles 5 --exercise-vpn-failure --disposable-network-test' internal/cli/lab_remote.go ||
    fail 'lab runner lost the qualifying PBP soak invocation'
grep -Fq 'socket.SO_PEERCRED' internal/cli/lab_remote.go ||
    fail 'lab VPN trigger no longer authenticates the malwarelab peer'
grep -Fq 'ActionServingReconcile' internal/lab/matrix.go ||
    fail 'lab qualification no longer dogfoods idempotent flow start serving'
grep -Fq 'RotateVNCSecret' internal/lab/e2e.go ||
    fail 'lab qualification no longer rotates the VNC credential through flow'
grep -Fq 'Name: "pbp-reboot-resume"' internal/lab/matrix.go ||
    fail 'lab qualification no longer reboots the PBP VM'
[[ "$(grep -Fc 'ActionPBPIdentity' internal/lab/matrix.go)" -eq 2 ]] ||
    fail 'lab qualification no longer compares the protected PBP persona across reboot'
if grep -Eq 'ssh-keyscan|(^|[^[:alnum:]_])scp[[:space:]]' \
    internal/cli/lab.go internal/cli/lab_remote.go internal/cli/lab_control.go; then
    fail 'lab runner contains an unpinned host-key or scp fallback'
fi

instance_sources=()
while IFS= read -r -d '' file; do
    [[ "$file" == *_test.go ]] || instance_sources+=("$file")
done < <(find internal/instances -maxdepth 1 -type f -name '*.go' -print0)
if ((${#instance_sources[@]} == 0)); then
    fail 'instance metadata package is missing'
fi
if grep -En '"os/exec"|exec[.]Command(Context)?[(]' "${instance_sources[@]}" >/dev/null; then
    fail 'local instance metadata package gained process/network execution'
fi

# the persistent target agent is intentionally only a fixed systemd timer
# invoking signed desired-state reconciliation. it must never grow a generic
# remote job/exec channel or place enrollment data in unit arguments.
instance_unit_source='internal/instanceunit/instanceunit.go'
grep -Fq 'ExecStart=` + executable + ` instance-runtime reconcile --state-root ` + stateRoot' "$instance_unit_source" ||
    fail 'target one-shot no longer invokes only fixed instance-runtime reconcile'
grep -Fq 'ConditionPathExists=` + filepath.Join(stateRoot, "runtime-config.json")' "$instance_unit_source" ||
    fail 'target one-shot is no longer inert before committed enrollment state'
grep -Fq 'OnCalendar=*:0/5' "$instance_unit_source" ||
    fail 'target retry cadence changed without security review'
grep -Fq 'Persistent=true' "$instance_unit_source" ||
    fail 'target timer is no longer reboot-persistent'
grep -Fq 'RandomizedDelaySec=45s' "$instance_unit_source" ||
    fail 'target timer lost bounded retry jitter'
[[ "$(grep -Ec 'exec[.]Command(Context)?[(]' "$instance_unit_source")" -eq 1 ]] ||
    fail 'target unit installer gained additional process execution'
grep -Fq 'exec.Command("/usr/bin/systemctl", arguments...)' "$instance_unit_source" ||
    fail 'target unit installer systemctl execution is no longer fixed'
if grep -Eq 'ExecStart=.*(instance exec|[[:space:]]ssh[[:space:]]|[[:space:]]scp[[:space:]]|--secret|--server)' "$instance_unit_source"; then
    fail 'target systemd unit gained a remote-command or secret-bearing argument'
fi

grep -Fq 'ReleasePublicKeySource string `json:"release_public_key_source,omitempty"`' internal/cli/serving.go ||
    fail 'serving reconcile no longer persists its public release-key source'
grep -Fq 'DesiredPublicKeySource string `json:"desired_public_key_source,omitempty"`' internal/cli/serving.go ||
    fail 'serving reconcile no longer persists its public desired-key source'
grep -Fq 'ControlPublicKeySource string `json:"control_public_key_source,omitempty"`' internal/cli/serving.go ||
    fail 'serving reconcile no longer persists its public control-key source'
grep -Fq 'ReleaseRoot            string `json:"release_root,omitempty"`' internal/cli/serving.go ||
    fail 'serving reconcile no longer persists its custom release root'
grep -Fq 'ServiceUser            string `json:"service_user,omitempty"`' internal/cli/serving.go ||
    fail 'serving reconcile no longer persists its dedicated service account'
grep -Fq 'reference.ServiceUser = defaultServingServiceUser' internal/cli/serving.go ||
    fail 'legacy serving references no longer receive the conservative service-account default'

grep -Fq 'desired.State.Revoked != IsRevocationAcknowledgement(report)' internal/serving/server.go ||
    fail 'serving no longer binds revocation status acknowledgement to desired state'
grep -Fq 'desired.State.Revoked != IsRevocationLogBatch(batch)' internal/serving/server.go ||
    fail 'serving no longer restricts revoked identities to the finite SSH event'

grep -Fq 'Component: "ssh", Version: "v0.1.5"' internal/cli/release.go ||
    fail 'mandatory SSH v0.1.5 revocation is missing from release construction'
grep -Fq 'run_enrollment </dev/tty' internal/cli/serving.go ||
    fail 'curl quickstart no longer reopens the controlling TTY for hidden enrollment input'
grep -Fq '"/usr/local/bin/flow", "instance-runtime", "secret", action, "--secret", "vnc"' internal/cli/instance.go ||
    fail 'VNC secret operation no longer uses the fixed target one-shot'
grep -Fq 'commandInstanceRuntimeSecret' internal/cli/instance_runtime.go ||
    fail 'fixed target VNC secret one-shot is missing'
grep -Fq 'runtimeConfigValue("PasswordFile")' internal/vncsecret/vncsecret_linux.go ||
    fail 'VNC rotation no longer verifies the active runtime password file'
grep -Fq 'unauthorized fixed public key' internal/cli/release.go ||
    fail 'SSH v0.1.5 revocation reason is missing'
grep -Fq '"-buildvcs=false"' internal/cli/release.go ||
    fail 'flow release artifacts may include non-reproducible VCS metadata'
grep -Fq 'retainedReleaseHighWater(root, setsRoot, historyRoot, publicKey)' internal/release/publish.go ||
    fail 'local release publish no longer derives rollback high-water from retained signed sets'
grep -Fq 'ensureManifestHistoryEntry(historyRoot, signed, publicKey)' internal/release/publish.go ||
    fail 'release publish no longer persists signed generation/version tombstones'
grep -Fq 'registerVersionBindings(versionHistory, signed.Manifest)' internal/release/publish.go ||
    fail 'release publish no longer enforces immutable component/version/target bindings'
grep -Fq 'release.CheckPublishPolicy(*root, stage.Signed, publicKey)' internal/cli/release.go ||
    fail 'local release publish plan no longer checks retained destination policy'
grep -Fq '"/v1/admin/releases/plan"' internal/cli/release.go internal/serving/server.go ||
    fail 'remote release publish plan no longer performs an authenticated policy preflight'
grep -Fq 'stat.Nlink != 1' internal/release/publish.go ||
    fail 'release path validation lost its single-link invariant'
grep -Fq 'syscall.O_NOFOLLOW' internal/release/bundle.go ||
    fail 'release bundle staging lost descriptor no-follow protection'
grep -Fq 'MaxBundleBytes' internal/release/bundle.go ||
    fail 'release bundle no longer enforces a hard aggregate size bound'
grep -Fq 'inspectCompressedArtifact' internal/release/bundle.go ||
    fail 'release bundle no longer rejects private keys inside compressed artifacts'
grep -Fq 'verifyOperatorReleaseCandidate(ctx, stage.Signed.Manifest)' internal/cli/release.go ||
    fail 'remote release publish no longer checks operator high-water before upload'
if grep -Fq 'len(os.Environ())' internal/cli/release.go; then
    fail 'release builders again inherit the complete operator environment'
fi

install -d -m 0700 "$static_tmp/state"
profile_output="$($flow_bin --home "$static_tmp/state" --source-root "$repo_root" profile show pbp)"
[[ "$profile_output" == *'Dependency order: ssh -> ssh-gui -> vpn-pbp-de -> pbp'* ]] ||
    fail 'PBP dependency order is not ssh -> ssh-gui -> vpn-pbp-de -> pbp'
[[ "$profile_output" == *'Artifacts: ssh, vpn, pbp'* ]] ||
    fail 'PBP release artifacts are not exactly ssh, vpn, pbp'

printf 'static-security: ok\n'
