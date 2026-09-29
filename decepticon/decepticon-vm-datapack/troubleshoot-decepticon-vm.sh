#!/usr/bin/env bash
set -u

out="${1:-${HOME}/decepticon-vm-diagnostic.txt}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
decepticon_home="${DECEPTICON_HOME:-${HOME}/.decepticon}"
install_dir="${DECEPTICON_SOURCE_DIR:-${HOME}/Decepticon-custom}"

exec > >(tee "$out") 2>&1

section() { printf '\n==== %s ====\n' "$*"; }
run() {
    printf '\n$ %s\n' "$*"
    "$@" || true
}

section "Summary"
date -Is || true
printf 'user=%s\n' "${USER:-unknown}"
printf 'home=%s\n' "$HOME"
printf 'TERM=%s\n' "${TERM:-unset}"
printf 'decepticon_home=%s\n' "$decepticon_home"
printf 'install_dir=%s\n' "$install_dir"
printf 'pack_dir=%s\n' "$script_dir"

section "Terminal"
run infocmp "${TERM:-xterm-256color}"
if [[ "${TERM:-}" = "xterm-kitty" ]] && ! infocmp xterm-kitty >/dev/null 2>&1; then
    cat <<'EOF'

TERM fix for this SSH session:
  export TERM=xterm-256color

Then retry htop:
  htop
EOF
fi

section "OS"
run uname -a
run cat /etc/os-release
run uptime
run free -h
run df -h

section "Packages"
run bash -lc 'command -v docker || true'
run bash -lc 'command -v htop || true'
run bash -lc 'command -v curl || true'
run bash -lc 'command -v jq || true'
run bash -lc 'command -v go || true'

section "Docker"
run id
run groups
run systemctl status docker --no-pager
run docker --version
run docker compose version
run docker ps
if ! docker ps >/dev/null 2>&1 && sudo -n docker ps >/dev/null 2>&1; then
    cat <<'EOF'

Docker works with sudo but not with your current user session.
Fix:
  newgrp docker
  cd ~/decepticon-vm-datapack  # or wherever you unpacked this pack
  ./bootstrap-decepticon-vm.sh --skip-docker

Alternative: log out and SSH back in.
EOF
fi
run docker images
run docker volume ls

section "Decepticon Files"
run ls -la "$decepticon_home"
run ls -la "$install_dir"
run bash -lc "command -v decepticon && decepticon --version"
run bash -lc "test -x /usr/local/bin/decepticon && /usr/local/bin/decepticon --version"
run ls -la "${HOME}/.local/bin/decepticon"

section "Compose Config"
if [[ -f "${decepticon_home}/docker-compose.yml" && -f "${decepticon_home}/.env" ]]; then
    (cd "$decepticon_home" && run docker compose --profile cli --profile web --profile c2-sliver --profile ad config --images)
    (cd "$decepticon_home" && run docker compose --profile cli ps)
else
    echo "No compose runtime files found yet in $decepticon_home"
fi

section "Maintainer Reference Guard"
if [[ -x "${install_dir}/scripts/decepticon-vm-ready.sh" ]]; then
    (cd "$install_dir" && run bash scripts/decepticon-vm-ready.sh --check-only)
else
    echo "VM-ready script not found in $install_dir"
fi

section "Recent Logs"
if [[ -f "${decepticon_home}/docker-compose.yml" && -f "${decepticon_home}/.env" ]]; then
    (cd "$decepticon_home" && run docker compose logs --tail=80 litellm langgraph sandbox skillogy)
fi

cat <<EOF

Diagnostic written to: $out
EOF
