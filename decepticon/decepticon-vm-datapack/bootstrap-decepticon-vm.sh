#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
bundle="${script_dir}/decepticon-custom-vm.tar.gz"
version_file="${script_dir}/VERSION"
install_dir="${HOME}/Decepticon-custom"
decepticon_home="${DECEPTICON_HOME:-${HOME}/.decepticon}"
bin_path="${DECEPTICON_BIN:-/usr/local/bin/decepticon}"
tag="${DECEPTICON_VERSION:-}"
install_docker=1
build_images=1
start_stack=0
run_onboard=0
core_only=0
with_reversing=0
force_extract=0
unsafe_open_docker_socket=0
verify_only=0
vpn_phase="full"
verified_bundle_sha=""
readonly DOCKER_TUNNEL_MTU=1280

usage() {
    cat <<'EOF'
Usage: ./bootstrap-decepticon-vm.sh [options]

Verifies the complete datapack, installs VM prerequisites, extracts the
bundled custom Decepticon version, and runs the local VM-ready script. It
never downloads Decepticon artifacts from the original maintainer.

Options:
  --bundle FILE       Copy of the bundle named in SHA256SUMS
                      (default: ./decepticon-custom-vm.tar.gz)
  --install-dir DIR   Extract custom source here (default: ~/Decepticon-custom)
  --home DIR          DECEPTICON_HOME runtime dir (default: ~/.decepticon)
  --bin PATH          Launcher install path (default: /usr/local/bin/decepticon)
  --tag TAG           Local launcher/runtime version tag (default: ./VERSION or custom-local)
  --skip-docker       Do not install Docker; require existing docker + compose
  --no-build          Do not build Decepticon Docker images
  --start             Run onboarding/start after preparation (interactive)
  --onboard           Run onboarding but do not start unless --start is also set
  --core-only         Build only core/CLI/web, skip optional C2/AD profiles
  --with-reversing    Also build reversing/Ghidra image (large download)
  --force-extract     Replace existing install dir by moving it to .bak.TIMESTAMP
  --verify-only       Verify checksums, paths and archive entry types, then exit
                      without changing packages, Docker, profiles or files.
  --vpn-only          Configure and verify the required Mullvad full tunnel,
                      then exit (used by the Toolkit quick installer).
  --vpn-ready         Verify an already prepared Mullvad tunnel, then continue
                      with the Decepticon system and image build.
  --unsafe-open-docker-socket
                      Last-resort single-user VM shortcut: chmod 666 docker.sock
                      so this current SSH session can use Docker without relogin.
  -h, --help          Show help

Typical flow:
  ./bootstrap-decepticon-vm.sh
  decepticon onboard --reset
  decepticon start
EOF
}

info() { printf '[vm-bootstrap] %s\n' "$*"; }
warn() { printf '[vm-bootstrap] warning: %s\n' "$*" >&2; }
die() {
    printf '[vm-bootstrap] error: %s\n' "$*" >&2
    exit 1
}

progress_phase() {
    local phase="$1"
    local progress_file=""
    if [[ -v TOOLKIT_PROGRESS_FILE ]]; then
        progress_file="$TOOLKIT_PROGRESS_FILE"
    fi

    case "$phase" in
    system | docker | source | runtime | launcher | images | network | finish) ;;
    *) return 0 ;;
    esac
    [[ -n "$progress_file" && -f "$progress_file" && ! -L "$progress_file" && -O "$progress_file" ]] ||
        return 0
    printf '%s\n' "$phase" >"$progress_file"
}

validate_bundle_archive() {
    local members_file types_file member clean listing kind invalid=0

    members_file="$(mktemp)"
    types_file="$(mktemp)"
    if ! tar -tzf "$bundle" >"$members_file" || [[ ! -s "$members_file" ]]; then
        rm -f "$members_file" "$types_file"
        die "bundle is empty or unreadable: $bundle"
    fi
    if ! LC_ALL=C tar -tvzf "$bundle" >"$types_file" || [[ ! -s "$types_file" ]]; then
        rm -f "$members_file" "$types_file"
        die "bundle entry types cannot be inspected: $bundle"
    fi

    while IFS= read -r listing; do
        kind="${listing%"${listing#?}"}"
        case "$kind" in
        - | d) ;;
        *)
            printf '[vm-bootstrap] error: bundle contains a link or unsupported entry type (%s)\n' "$kind" >&2
            invalid=1
            ;;
        esac
    done <"$types_file"

    while IFS= read -r member; do
        clean="${member#./}"
        clean="${clean%/}"
        [[ -n "$clean" ]] || continue
        case "$clean" in
        /* | .. | ../* | */../* | */..)
            printf '[vm-bootstrap] error: unsafe bundle path: %s\n' "$member" >&2
            invalid=1
            ;;
        esac
    done <"$members_file"

    rm -f "$members_file" "$types_file"
    [[ "$invalid" == 0 ]] || die "bundle member validation failed"
}

verify_datapack_integrity() {
    local manifest="${script_dir}/SHA256SUMS"
    local expected=""
    local checksum filename actual

    command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required to verify the datapack"
    command -v tar >/dev/null 2>&1 || die "tar is required to verify the datapack"
    command -v mktemp >/dev/null 2>&1 || die "mktemp is required to verify the datapack"
    [[ -f "$manifest" ]] || die "checksum manifest not found: $manifest"
    [[ -f "$bundle" ]] || die "bundle not found: $bundle"

    info "verifying datapack checksums before making system changes"
    (cd "$script_dir" && sha256sum --strict -c SHA256SUMS) ||
        die "datapack checksum verification failed"

    while read -r checksum filename; do
        if [[ "$filename" == decepticon-custom-vm.tar.gz ]]; then
            expected="$checksum"
            break
        fi
    done <"$manifest"

    [[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] ||
        die "SHA256SUMS has no valid decepticon-custom-vm.tar.gz entry"
    actual="$(sha256sum "$bundle")"
    actual="${actual%% *}"
    [[ "$actual" == "$expected" ]] ||
        die "selected bundle does not match SHA256SUMS: $bundle"
    verified_bundle_sha="$actual"
    validate_bundle_archive
}

while (($#)); do
    case "$1" in
    --bundle)
        [[ $# -ge 2 ]] || die "--bundle needs a file"
        bundle="$2"
        shift 2
        ;;
    --install-dir)
        [[ $# -ge 2 ]] || die "--install-dir needs a dir"
        install_dir="$2"
        shift 2
        ;;
    --home)
        [[ $# -ge 2 ]] || die "--home needs a dir"
        decepticon_home="$2"
        shift 2
        ;;
    --bin)
        [[ $# -ge 2 ]] || die "--bin needs a path"
        bin_path="$2"
        shift 2
        ;;
    --tag)
        [[ $# -ge 2 ]] || die "--tag needs a value"
        tag="$2"
        shift 2
        ;;
    --skip-docker)
        install_docker=0
        shift
        ;;
    --no-build)
        build_images=0
        shift
        ;;
    --start)
        start_stack=1
        run_onboard=1
        shift
        ;;
    --onboard)
        run_onboard=1
        shift
        ;;
    --core-only)
        core_only=1
        shift
        ;;
    --with-reversing)
        with_reversing=1
        shift
        ;;
    --force-extract)
        force_extract=1
        shift
        ;;
    --verify-only)
        verify_only=1
        shift
        ;;
    --vpn-only)
        [[ "$vpn_phase" == "full" ]] || die "--vpn-only and --vpn-ready are mutually exclusive"
        vpn_phase="only"
        shift
        ;;
    --vpn-ready)
        [[ "$vpn_phase" == "full" ]] || die "--vpn-only and --vpn-ready are mutually exclusive"
        vpn_phase="ready"
        shift
        ;;
    --unsafe-open-docker-socket)
        unsafe_open_docker_socket=1
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *) die "unknown option: $1" ;;
    esac
done

for path_value in "$decepticon_home" "$bin_path"; do
    [[ "$path_value" == /* ]] || die "--home and --bin must use absolute paths"
    [[ "$path_value" != *[!A-Za-z0-9_./@+-]* ]] ||
        die "--home and --bin contain unsupported path characters"
    case "/${path_value#/}/" in
    */../*) die "--home and --bin must not contain '..' path components" ;;
    esac
done
[[ "$(dirname "$bin_path")" != *:* ]] || die "launcher directory must not contain ':'"
[[ "$(basename "$bin_path")" == decepticon ]] || die "--bin must end in /decepticon"
case "$bin_path" in
/usr/local/bin/decepticon | "${HOME}"/*/decepticon) ;;
*) die "--bin must be /usr/local/bin/decepticon or below $HOME" ;;
esac

bin_dir="$(dirname "$bin_path")"
[[ -d "$bin_dir" ]] || die "--bin parent directory must already exist: $bin_dir"
canonical_bin_dir="$(cd -- "$bin_dir" && pwd -P)" ||
    die "cannot resolve launcher directory: $bin_dir"
if [[ "$bin_path" == /usr/local/bin/decepticon ]]; then
    [[ "$canonical_bin_dir" == /usr/local/bin ]] ||
        die "/usr/local/bin must resolve to /usr/local/bin"
else
    canonical_home="$(cd -- "$HOME" && pwd -P)" || die "cannot resolve HOME: $HOME"
    case "$canonical_bin_dir" in
    "$canonical_home" | "$canonical_home"/*) ;;
    *) die "--bin parent resolves outside HOME: $canonical_bin_dir" ;;
    esac
fi

case "$(uname -s)" in
Linux) ;;
*) die "Linux VM required" ;;
esac

verify_datapack_integrity

if [[ "$verify_only" == 1 ]]; then
    info "datapack checksums and archive members are valid"
    exit 0
fi

if ((EUID == 0)) && [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != root ]]; then
    die "run this bootstrap as ${SUDO_USER}, not with sudo; it requests sudo only for system changes"
fi

if [[ -z "$tag" && -f "$version_file" ]]; then
    tag="$(tr -d '[:space:]' <"$version_file")"
fi
tag="${tag:-custom-local}"

fix_terminal() {
    if [[ -n "${TERM:-}" ]] && ! infocmp "$TERM" >/dev/null 2>&1; then
        warn "TERM=$TERM is not known on this VM; using xterm-256color for this session"
        export TERM=xterm-256color
    fi

    local profile="${HOME}/.profile"
    local marker='decepticon-vm term fallback'
    if [[ -w "$HOME" ]] && ! grep -q "$marker" "$profile" 2>/dev/null; then
        cat >>"$profile" <<'EOF'

# decepticon-vm term fallback
if [ "${TERM:-}" = "xterm-kitty" ] && ! infocmp xterm-kitty >/dev/null 2>&1; then
  export TERM=xterm-256color
fi
EOF
        info "added xterm-kitty fallback to ~/.profile"
    fi
}

ensure_user_path() {
    local bindir quoted_bindir
    bindir="$(dirname "$bin_path")"
    if [[ ! -d "$bindir" ]]; then
        if mkdir -p "$bindir" 2>/dev/null; then
            chmod 0755 "$bindir"
        elif ((EUID == 0)); then
            install -d -m 0755 "$bindir"
        else
            command -v sudo >/dev/null 2>&1 ||
                die "cannot create launcher directory without sudo: $bindir"
            sudo install -d -m 0755 "$bindir"
        fi
    fi

    if [[ ":${PATH}:" != *":${bindir}:"* ]]; then
        export PATH="${bindir}:${PATH}"
    fi

    local profile="${HOME}/.profile"
    local marker='decepticon-vm local bin path'
    if [[ -w "$HOME" ]] && ! grep -q "$marker" "$profile" 2>/dev/null; then
        printf -v quoted_bindir '%q' "$bindir"
        cat >>"$profile" <<EOF

# ${marker}
case ":\$PATH:" in
  *:${quoted_bindir}:*) ;;
  *) export PATH=${quoted_bindir}:"\$PATH" ;;
esac
EOF
        info "added ${bindir} to ~/.profile"
    fi
}

sudo_noninteractive_or_prompt() {
    if ((EUID == 0)); then
        "$@"
        return
    fi

    command -v sudo >/dev/null 2>&1 ||
        die "root privileges are required and sudo is not installed"
    sudo "$@"
}

mullvad_root() {
    sudo_noninteractive_or_prompt env LC_ALL=C /usr/bin/mullvad "$@"
}

mullvad_is_ready() {
    local status_json anti_censorship tunnel split_tunnel auto_connect lockdown lan egress

    command -v /usr/bin/mullvad >/dev/null 2>&1 || return 1
    command -v jq >/dev/null 2>&1 || return 1
    command -v curl >/dev/null 2>&1 || return 1

    status_json="$(mullvad_root status --json 2>/dev/null)" || return 1
    jq -e '
    .state == "connected"
    and .details.endpoint.obfuscation.Single.obfuscation_type == "Shadowsocks"
    and (.details.endpoint.obfuscation.Single.endpoint.address | endswith(":443"))
  ' <<<"$status_json" >/dev/null || return 1

    anti_censorship="$(mullvad_root anti-censorship get 2>/dev/null)" || return 1
    grep -Fxq 'mode: shadowsocks' <<<"$anti_censorship" || return 1
    grep -Fxq 'shadowsocks settings: port 443' <<<"$anti_censorship" || return 1

    tunnel="$(mullvad_root tunnel get 2>/dev/null)" || return 1
    grep -Eq '^[[:space:]]*Allowed IPs:[[:space:]]*0[.]0[.]0[.]0/0[[:space:]]*$' <<<"$tunnel" || return 1
    grep -Eq '^[[:space:]]*IPv6:[[:space:]]*off[[:space:]]*$' <<<"$tunnel" || return 1
    [[ "$(</proc/sys/net/ipv6/conf/all/disable_ipv6)" == 1 ]] || return 1

    split_tunnel="$(mullvad_root split-tunnel list 2>/dev/null)" || return 1
    [[ "$split_tunnel" == 'Excluded PIDs:' ]] || return 1
    lan="$(mullvad_root lan get 2>/dev/null)" || return 1
    grep -Eiq '(^|[[:space:]:])allow([[:space:]]|$)' <<<"$lan" || return 1
    auto_connect="$(mullvad_root auto-connect get 2>/dev/null)" || return 1
    lockdown="$(mullvad_root lockdown-mode get 2>/dev/null)" || return 1
    grep -Eiq '(^|[[:space:]:])on([[:space:]]|$)' <<<"$auto_connect" || return 1
    grep -Eiq '(^|[[:space:]:])on([[:space:]]|$)' <<<"$lockdown" || return 1

    egress="$(curl -4 --disable --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 30 --retry 2 --retry-delay 1 \
        https://am.i.mullvad.net/json 2>/dev/null)" || return 1
    jq -e '.mullvad_exit_ip == true' <<<"$egress" >/dev/null || return 1
}

verify_mullvad_ready() {
    info "verifying Mullvad full tunnel, Shadowsocks port 443 and lockdown"
    mullvad_is_ready ||
        die "Mullvad is not fail-closed through Shadowsocks port 443; rerun the foreground VPN phase"
}

configure_decepticon_mullvad_lan() {
    info "allowing Mullvad local networking for Decepticon Docker bridges"
    mullvad_root lan set allow >/dev/null ||
        die "could not enable Mullvad local networking required by Decepticon"
}

prepare_mullvad() {
    local setup="$script_dir/setup-mullvad.sh"

    [[ -x "$setup" && ! -L "$setup" ]] || die "verified Mullvad setup is missing: $setup"
    info "configuring the VM-wide Mullvad tunnel before Docker downloads or builds"
    "$setup" --skip-firefox --return-after-install
    configure_decepticon_mullvad_lan
    verify_mullvad_ready
}

install_base_packages() {
    if ! command -v apt-get >/dev/null 2>&1; then
        warn "apt-get not found; skipping base package install"
        return 0
    fi

    info "installing base VM tools"
    sudo_noninteractive_or_prompt env DEBIAN_FRONTEND=noninteractive apt-get update
    sudo_noninteractive_or_prompt env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        ca-certificates curl gnupg lsb-release tar gzip unzip jq htop git make ncurses-term

    sudo_noninteractive_or_prompt env DEBIAN_FRONTEND=noninteractive apt-get install -y kitty-terminfo >/dev/null 2>&1 || true
}

install_docker_apt() {
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        info "Docker + Compose already installed"
        return 0
    fi

    command -v apt-get >/dev/null 2>&1 || die "Docker auto-install supports apt-based Ubuntu/Debian only"
    . /etc/os-release
    local distro="${ID:-}"
    case "$distro" in
    ubuntu | debian) ;;
    *) die "unsupported distro for Docker auto-install: ${PRETTY_NAME:-$distro}" ;;
    esac

    info "installing Docker Engine from Docker's official ${distro} apt repo"
    sudo_noninteractive_or_prompt env DEBIAN_FRONTEND=noninteractive apt-get update
    sudo_noninteractive_or_prompt env DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg
    sudo_noninteractive_or_prompt install -m 0755 -d /etc/apt/keyrings

    local keyring="/etc/apt/keyrings/docker.gpg"
    if [[ ! -f "$keyring" ]]; then
        curl -fsSL "https://download.docker.com/linux/${distro}/gpg" | sudo_noninteractive_or_prompt gpg --dearmor -o "$keyring"
        sudo_noninteractive_or_prompt chmod a+r "$keyring"
    fi

    local codename="${VERSION_CODENAME:-$(lsb_release -cs)}"
    echo "deb [arch=$(dpkg --print-architecture) signed-by=${keyring}] https://download.docker.com/linux/${distro} ${codename} stable" |
        sudo_noninteractive_or_prompt tee /etc/apt/sources.list.d/docker.list >/dev/null

    sudo_noninteractive_or_prompt env DEBIAN_FRONTEND=noninteractive apt-get update
    sudo_noninteractive_or_prompt env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    sudo_noninteractive_or_prompt systemctl enable --now docker || true

    local docker_user="${SUDO_USER:-${USER:-}}"
    if [[ -n "$docker_user" && "$docker_user" != root ]] &&
        getent group docker >/dev/null 2>&1; then
        sudo_noninteractive_or_prompt usermod -aG docker "$docker_user" || true
    fi
}

configure_docker_tunnel_mtu() (
    set -Eeuo pipefail

    local config_dir='/etc/docker'
    local config_path="${config_dir}/daemon.json"
    local work_dir input_config rendered_config staged_config active_containers bridge_mtu
    local had_config=0

    command -v jq >/dev/null 2>&1 || die "jq is required to configure Docker safely"
    command -v dockerd >/dev/null 2>&1 || die "dockerd is required to configure Docker safely"

    work_dir="$(mktemp -d)"
    trap 'rm -rf -- "$work_dir"' EXIT
    input_config="${work_dir}/daemon.json.input"
    rendered_config="${work_dir}/daemon.json.rendered"

    if sudo_noninteractive_or_prompt test -e "$config_path"; then
        sudo_noninteractive_or_prompt test -f "$config_path" ||
            die "Docker daemon config is not a regular file: $config_path"
        if sudo_noninteractive_or_prompt test -L "$config_path"; then
            die "refusing to replace Docker daemon config symlink: $config_path"
        fi
        sudo_noninteractive_or_prompt cat "$config_path" >"$input_config"
        had_config=1
    else
        printf '{}\n' >"$input_config"
    fi
    chmod 0600 "$input_config"

    jq -e '
    type == "object"
    and ((.["default-network-opts"] // {}) | type == "object")
    and (((.["default-network-opts"] // {}).bridge // {}) | type == "object")
  ' "$input_config" >/dev/null ||
        die "Docker daemon config must be a JSON object with object-valued network options"

    jq --arg mtu "$DOCKER_TUNNEL_MTU" '
    .mtu = ($mtu | tonumber)
    | .["default-network-opts"] = (
        (.["default-network-opts"] // {}) as $options
        | $options + {
            "bridge": (($options.bridge // {}) + {
              "com.docker.network.driver.mtu": $mtu
            })
          }
      )
  ' "$input_config" >"$rendered_config"
    chmod 0600 "$rendered_config"

    sudo_noninteractive_or_prompt dockerd --validate --config-file "$rendered_config" >/dev/null ||
        die "generated Docker daemon config did not validate"

    if cmp -s "$input_config" "$rendered_config"; then
        info "Docker bridge MTU is already configured for the Mullvad tunnel"
    else
        active_containers="$(sudo_noninteractive_or_prompt docker ps -q)"
        [[ -z "$active_containers" ]] ||
            die "Docker MTU must change, but containers are already running; stop them before retrying"

        if sudo_noninteractive_or_prompt test -e "$config_dir"; then
            sudo_noninteractive_or_prompt test -d "$config_dir" ||
                die "Docker config path is not a directory: $config_dir"
            if sudo_noninteractive_or_prompt test -L "$config_dir"; then
                die "refusing to use Docker config directory symlink: $config_dir"
            fi
        else
            sudo_noninteractive_or_prompt install -d -m 0755 "$config_dir"
        fi

        staged_config="${config_dir}/.daemon.json.toolkit.$$"
        sudo_noninteractive_or_prompt install -m 0600 "$rendered_config" "$staged_config"
        sudo_noninteractive_or_prompt mv -f -- "$staged_config" "$config_path"

        if ! sudo_noninteractive_or_prompt systemctl restart docker; then
            warn "Docker restart failed; restoring the previous daemon config"
            if [[ "$had_config" == 1 ]]; then
                staged_config="${config_dir}/.daemon.json.rollback.$$"
                sudo_noninteractive_or_prompt install -m 0600 "$input_config" "$staged_config"
                sudo_noninteractive_or_prompt mv -f -- "$staged_config" "$config_path"
            else
                sudo_noninteractive_or_prompt rm -f -- "$config_path"
            fi
            sudo_noninteractive_or_prompt systemctl restart docker >/dev/null 2>&1 || true
            die "Docker could not restart with the tunnel-safe MTU"
        fi
        info "configured Docker bridge networks with MTU ${DOCKER_TUNNEL_MTU}"
    fi

    sudo_noninteractive_or_prompt systemctl is-active --quiet docker ||
        die "Docker is not active after MTU configuration"
    [[ -r /sys/class/net/docker0/mtu ]] || die "Docker default bridge is missing"
    bridge_mtu="$(</sys/class/net/docker0/mtu)"
    [[ "$bridge_mtu" == "$DOCKER_TUNNEL_MTU" ]] ||
        die "Docker default bridge MTU is $bridge_mtu, expected $DOCKER_TUNNEL_MTU"
)

ensure_docker_access() {
    command -v docker >/dev/null 2>&1 || die "docker command still missing"
    docker compose version >/dev/null 2>&1 || die "docker compose plugin still missing"

    if docker ps >/dev/null 2>&1; then
        info "Docker is usable by this SSH session"
        return 0
    fi

    if [[ "$unsafe_open_docker_socket" == 1 && -S /var/run/docker.sock ]]; then
        warn "opening /var/run/docker.sock for this single-user VM session"
        sudo_noninteractive_or_prompt chmod 666 /var/run/docker.sock
        docker ps >/dev/null 2>&1 && return 0
    fi

    if ((EUID != 0)) && command -v sudo >/dev/null 2>&1 &&
        (sudo -n docker ps >/dev/null 2>&1 || sudo docker ps >/dev/null 2>&1); then
        cat >&2 <<EOF

Docker is installed, but this SSH session is not yet in the docker group.
Run ONE of these, then rerun this script:

  newgrp docker
  cd "${script_dir}"
  ./bootstrap-decepticon-vm.sh --skip-docker

Or log out and SSH back in, then rerun:

  cd "${script_dir}"
  ./bootstrap-decepticon-vm.sh --skip-docker

Single-user throwaway VM shortcut, less safe:

  ./bootstrap-decepticon-vm.sh --skip-docker --unsafe-open-docker-socket
EOF
        exit 20
    fi

    die "Docker daemon is not reachable; run ./troubleshoot-decepticon-vm.sh"
}

extract_custom_bundle() {
    [[ -f "$bundle" ]] || die "bundle not found: $bundle"

    local current_sha marker wanted_sha
    wanted_sha="$(sha256sum "$bundle" | awk '{print $1}')"
    [[ -n "$verified_bundle_sha" && "$wanted_sha" == "$verified_bundle_sha" ]] ||
        die "bundle changed after datapack verification"
    marker="${install_dir}/.decepticon-bundle.sha256"

    if [[ -e "$install_dir" || -L "$install_dir" ]]; then
        current_sha="$(cat "$marker" 2>/dev/null || true)"
        if [[ "$current_sha" == "$wanted_sha" ]]; then
            info "using existing install dir: $install_dir"
            return 0
        fi

        if [[ "$force_extract" != 1 ]]; then
            if [[ ! "$current_sha" =~ ^[[:xdigit:]]{64}$ ]]; then
                die "install dir is not a managed bundle: $install_dir (use --force-extract to back it up and replace it)"
            fi
            info "managed bundle changed; backing up the previous source before upgrade"
        fi

        local backup="${install_dir}.bak.$(date +%Y%m%d%H%M%S)"
        [[ ! -e "$backup" && ! -L "$backup" ]] || backup="${backup}.$$"
        mv "$install_dir" "$backup"
        info "moved existing install dir to $backup"
    fi

    mkdir -p "$install_dir"
    info "extracting custom Decepticon bundle to $install_dir"
    tar -xzf "$bundle" -C "$install_dir"
    printf '%s\n' "$wanted_sha" >"$marker"
}

prepare_bundled_launcher() {
    local launcher_dir="${install_dir}/clients/launcher/bin"
    local launcher="${launcher_dir}/decepticon"
    local bundled="" version_output

    case "$(uname -m)" in
    x86_64 | amd64) bundled="${launcher_dir}/decepticon-linux-amd64" ;;
    aarch64 | arm64) bundled="${launcher_dir}/decepticon-linux-arm64" ;;
    esac

    if [[ -n "$bundled" && -f "$bundled" ]]; then
        chmod 755 "$bundled"
        version_output="$("$bundled" --version 2>/dev/null)" ||
            die "bundled launcher cannot run on this VM: $bundled"
        [[ "$version_output" == "Decepticon $tag" ]] ||
            die "bundled launcher version does not match datapack tag $tag"
        cp "$bundled" "$launcher"
        chmod 755 "$launcher"
        info "selected bundled launcher for $(uname -m)"
        return 0
    fi

    if [[ -f "$launcher" ]]; then
        chmod 755 "$launcher"
        version_output="$("$launcher" --version 2>/dev/null)" ||
            die "bundled launcher has the wrong architecture"
        [[ "$version_output" == "Decepticon $tag" ]] ||
            die "bundled launcher version does not match datapack tag $tag"
        info "using verified legacy bundled launcher"
        return 0
    fi

    if command -v go >/dev/null 2>&1; then
        info "no matching prebuilt launcher found; Go will build one natively"
        return 0
    fi

    die "no launcher for $(uname -m); install Go so the launcher can be built natively"
}

run_vm_ready() {
    [[ -x "${install_dir}/scripts/decepticon-vm-ready.sh" ]] || die "missing VM-ready script in $install_dir"

    local args=(--home "$decepticon_home" --bin "$bin_path" --tag "$tag")
    [[ "$build_images" == 0 ]] && args+=(--no-build)
    [[ "$start_stack" == 0 ]] && args+=(--no-start)
    [[ "$run_onboard" == 0 ]] && args+=(--no-onboard)
    [[ "$core_only" == 1 ]] && args+=(--core-only)
    [[ "$with_reversing" == 1 ]] && args+=(--with-reversing)

    info "running custom VM-ready script"
    (cd "$install_dir" && scripts/decepticon-vm-ready.sh "${args[@]}")
}

if [[ "$vpn_phase" == "ready" ]]; then
    configure_decepticon_mullvad_lan
    verify_mullvad_ready
else
    prepare_mullvad
    if [[ "$vpn_phase" == "only" ]]; then
        info "Mullvad foreground phase completed; normal traffic is fail-closed through Shadowsocks port 443"
        exit 0
    fi
fi

progress_phase system
fix_terminal
ensure_user_path
install_base_packages
progress_phase docker
if [[ "$install_docker" == 1 ]]; then
    install_docker_apt
fi
configure_docker_tunnel_mtu
ensure_docker_access
verify_mullvad_ready
progress_phase source
extract_custom_bundle
prepare_bundled_launcher
progress_phase runtime
run_vm_ready
progress_phase finish

if [[ "$decepticon_home" == "${HOME}/.decepticon" ]]; then
    cat <<'EOF'

VM preparation finished.

Decepticon commands are ready:
  decepticon --version
  decepticon onboard --reset
  decepticon start
  ./troubleshoot-decepticon-vm.sh
EOF
else
    printf -v quoted_home '%q' "$decepticon_home"
    cat <<EOF

VM preparation finished with custom DECEPTICON_HOME.

Use:
  DECEPTICON_HOME=${quoted_home} decepticon --version
  DECEPTICON_HOME=${quoted_home} decepticon onboard --reset
  DECEPTICON_HOME=${quoted_home} decepticon start
  ./troubleshoot-decepticon-vm.sh
EOF
fi
