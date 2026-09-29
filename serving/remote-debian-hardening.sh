#!/usr/bin/env bash
set -Eeuo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

mode="${1:-}"
admin="${2:-}"
port="${3:-}"
key="${4:-}"
profile="${5:-}"

state_dir=/var/lib/toolkit-provision
prepared_file="${state_dir}/prepared"
rollback_dir="${state_dir}/rollback"
helper=/usr/local/libexec/toolkit-remote-hardening
sshd_dropin=/etc/ssh/sshd_config.d/00-toolkit-hardening.conf
nft_include=/etc/nftables.d/toolkit-filter.nft
sysctl_dropin=/etc/sysctl.d/99-toolkit-hardening.conf
auto_upgrades=/etc/apt/apt.conf.d/20auto-upgrades

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

validate_identity() {
    [[ "$admin" != download ]] || die 'admin user download is reserved for publishing'
    [[ "$admin" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die 'invalid admin user'
    [[ "$port" =~ ^[0-9]+$ ]] && ((10#$port > 0 && 10#$port < 65536)) || die 'invalid SSH port'
    case "$profile" in
    serving | worker | gui) ;;
    *) die 'profile must be serving, worker or gui' ;;
    esac
}

require_root_debian() {
    [[ "$(id -u)" == 0 ]] || die 'root required'
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ "$ID" == debian && "$VERSION_ID" == 13 ]] || die 'Debian 13 required'
}

install_baseline_settings() {
    install -d -m 0755 /etc/sysctl.d /etc/apt/apt.conf.d
    cat >"$sysctl_dropin" <<'EOF'
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.unprivileged_bpf_disabled=1
fs.protected_fifos=2
fs.protected_hardlinks=1
fs.protected_regular=2
fs.protected_symlinks=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
EOF
    chmod 0644 "$sysctl_dropin"
    sysctl --system >/dev/null
    cat >"$auto_upgrades" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    chmod 0644 "$auto_upgrades"
}

render_sshd() {
    cat <<EOF
Port $port
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
GatewayPorts no
AllowStreamLocalForwarding no
PermitTunnel no
PermitUserEnvironment no
MaxAuthTries 3
LoginGraceTime 30
DebianBanner no
AllowUsers $admin download
EOF

    if [[ "$profile" == gui ]]; then
        cat <<EOF
Match User $admin
AllowTcpForwarding local
PermitOpen 127.0.0.1:5901 [::1]:5901
Match User download
AllowTcpForwarding no
Match all
EOF
    else
        printf '%s\n' 'AllowTcpForwarding no'
    fi
}

render_nft() {
    cat <<EOF
table inet toolkit-filter {
  chain input {
    type filter hook input priority filter; policy drop;
    ct state established,related accept
    ct state invalid drop
    iifname "lo" accept
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
    tcp dport $port accept
EOF

    if [[ "$profile" == serving ]]; then
        printf '%s\n' '    tcp dport { 80, 443 } accept'
    fi

    cat <<'EOF'
  }
EOF

    if [[ "$profile" != worker ]]; then
        cat <<'EOF'
  chain forward {
    type filter hook forward priority filter; policy drop;
  }
EOF
    fi

    cat <<'EOF'
  chain output {
    type filter hook output priority filter; policy accept;
  }
}
EOF
}

write_prepared_state() {
    install -d -m 0700 "$state_dir"
    local candidate
    candidate="$(mktemp "${state_dir}/.prepared.XXXXXX")"
    printf '%s\n%s\n%s\n' "$admin" "$port" "$profile" >"$candidate"
    chmod 0600 "$candidate"
    mv -f -- "$candidate" "$prepared_file"
}

prepared_state_matches() {
    [[ -f "$prepared_file" && ! -L "$prepared_file" ]] || return 1
    [[ "$(sed -n '1p' "$prepared_file")" == "$admin" ]] || return 1
    [[ "$(sed -n '2p' "$prepared_file")" == "$port" ]] || return 1
    [[ "$(sed -n '3p' "$prepared_file")" == "$profile" ]] || return 1
}

prepare_system() {
    require_root_debian
    [[ -f "$key" && ! -L "$key" && "$(wc -l <"$key")" == 1 ]] || die 'unsafe public key file'
    grep -Eq '^ssh-(ed25519|rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+' "$key" || die 'invalid public key'

    if ! prepared_state_matches; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get -y full-upgrade
        apt-get install -y ca-certificates curl nftables openssh-server procps sudo unattended-upgrades
    fi

    install_baseline_settings
    id "$admin" >/dev/null 2>&1 || useradd -m -s /bin/bash "$admin"
    usermod -aG sudo "$admin"
    passwd -l "$admin" >/dev/null

    local home group deploy_home deploy_group
    home="$(getent passwd "$admin" | cut -d: -f6)"
    group="$(id -gn "$admin")"
    [[ "$home" == /home/* ]] || die 'unsafe admin home'
    install -d -m 0700 -o "$admin" -g "$group" "$home/.ssh"
    install -m 0600 -o "$admin" -g "$group" "$key" "$home/.ssh/authorized_keys"
    id download >/dev/null 2>&1 || useradd -m -s /bin/bash download
    passwd -l download >/dev/null
    deploy_home="$(getent passwd download | cut -d: -f6)"
    deploy_group="$(id -gn download)"
    [[ "$deploy_home" == /home/download ]] || die 'unsafe download home'
    install -d -m 0700 -o download -g "$deploy_group" "$deploy_home/.ssh"
    install -m 0600 -o download -g "$deploy_group" "$key" "$deploy_home/.ssh/authorized_keys"
    printf '%s ALL=(ALL:ALL) NOPASSWD: ALL\n' "$admin" >"/etc/sudoers.d/90-toolkit-$admin"
    chmod 0440 "/etc/sudoers.d/90-toolkit-$admin"
    visudo -cf "/etc/sudoers.d/90-toolkit-$admin" >/dev/null
    write_prepared_state
}

backup_path() {
    local source="$1" name="$2"
    if [[ -e "$source" ]]; then
        [[ -f "$source" && ! -L "$source" ]] || die "unsafe path to back up: $source"
        cp -a -- "$source" "${rollback_dir}/${name}"
        : >"${rollback_dir}/${name}.present"
    fi
}

arm_rollback() {
    [[ ! -e "$rollback_dir" ]] || die 'a provisioning rollback is already armed'
    install -d -m 0700 "$rollback_dir" /usr/local/libexec
    backup_path "$sshd_dropin" sshd.conf
    backup_path "$nft_include" nft.conf
    backup_path /etc/nftables.conf nftables.conf
    if nft list table inet toolkit-filter >"${rollback_dir}/nft.live" 2>/dev/null; then
        : >"${rollback_dir}/nft.live.present"
    else
        rm -f -- "${rollback_dir}/nft.live"
    fi
    install -m 0700 "$0" "$helper"
    systemctl stop toolkit-provision-rollback.timer toolkit-provision-rollback.service >/dev/null 2>&1 || true
    systemd-run --quiet --unit=toolkit-provision-rollback --on-active=5m "$helper" rollback
}

apply_nft_candidate() {
    local desired="$1" batch="$2"
    if nft list table inet toolkit-filter >/dev/null 2>&1; then
        {
            printf '%s\n' 'delete table inet toolkit-filter'
            cat "$desired"
        } >"$batch"
    else
        cp -- "$desired" "$batch"
    fi
    nft --check -f "$batch"
    nft -f "$batch"
    install -d -m 0755 /etc/nftables.d
    install -m 0644 "$desired" "$nft_include"
    grep -qF 'include "/etc/nftables.d/*.nft"' /etc/nftables.conf ||
        printf '%s\n' 'include "/etc/nftables.d/*.nft"' >>/etc/nftables.conf
}

validate_effective_sshd() {
    local effective="$1"
    grep -Fqx 'permitrootlogin no' <<<"$effective" || die 'effective root-login policy mismatch'
    grep -Fqx 'passwordauthentication no' <<<"$effective" || die 'effective password policy mismatch'
    grep -c '^allowusers ' <<<"$effective" | grep -Fqx '2' || die 'effective allowusers policy has unexpected entries'
    grep -Fqx "allowusers $admin" <<<"$effective" || die 'effective admin allowusers policy mismatch'
    grep -Fqx 'allowusers download' <<<"$effective" || die 'effective download allowusers policy mismatch'
    if [[ "$profile" == gui ]]; then
        grep -Fqx 'allowtcpforwarding local' <<<"$effective" || die 'effective GUI forwarding policy mismatch'
    else
        grep -Fqx 'allowtcpforwarding no' <<<"$effective" || die 'effective forwarding policy mismatch'
    fi
}

activate_system() {
    require_root_debian
    prepared_state_matches || die 'prepare state is missing or does not match this activation'
    id "$admin" >/dev/null 2>&1 || die 'prepared admin is missing'
    sudo -u "$admin" sudo -n true || die 'prepared admin does not have noninteractive sudo'

    local candidate_dir ssh_candidate nft_candidate nft_batch effective
    candidate_dir="$(mktemp -d "${state_dir}/activate.XXXXXX")"
    trap 'rm -rf -- "$candidate_dir"' RETURN
    ssh_candidate="${candidate_dir}/sshd.conf"
    nft_candidate="${candidate_dir}/nft.conf"
    nft_batch="${candidate_dir}/nft.batch"
    render_sshd >"$ssh_candidate"
    render_nft >"$nft_candidate"
    chmod 0600 "$ssh_candidate" "$nft_candidate"

    sshd -t -f "$ssh_candidate"
    if nft list table inet toolkit-filter >/dev/null 2>&1; then
        {
            printf '%s\n' 'delete table inet toolkit-filter'
            cat "$nft_candidate"
        } >"$nft_batch"
    else
        cp -- "$nft_candidate" "$nft_batch"
    fi
    nft --check -f "$nft_batch"

    arm_rollback
    trap 'rollback_system' EXIT
    install -d -m 0755 /etc/ssh/sshd_config.d
    install -m 0644 "$ssh_candidate" "$sshd_dropin"
    if ! sshd -t; then
        rollback_system
        die 'effective sshd configuration is invalid; rollback completed'
    fi

    apply_nft_candidate "$nft_candidate" "$nft_batch"
    systemctl enable nftables ssh unattended-upgrades >/dev/null
    systemctl enable --now unattended-upgrades >/dev/null
    systemctl reload ssh
    systemctl is-active --quiet ssh

    effective="$(sshd -T -C user="$admin",host=localhost,addr=127.0.0.1)"
    validate_effective_sshd "$effective"
    trap - EXIT
}

restore_file() {
    local target="$1" name="$2"
    if [[ -f "${rollback_dir}/${name}.present" ]]; then
        install -m 0644 "${rollback_dir}/${name}" "$target"
    else
        rm -f -- "$target"
    fi
}

rollback_system() {
    require_root_debian
    [[ -d "$rollback_dir" && ! -L "$rollback_dir" ]] || exit 0
    restore_file "$sshd_dropin" sshd.conf
    install -d -m 0755 /etc/nftables.d
    restore_file "$nft_include" nft.conf
    restore_file /etc/nftables.conf nftables.conf

    local batch
    batch="${rollback_dir}/restore.batch"
    : >"$batch"
    if nft list table inet toolkit-filter >/dev/null 2>&1; then
        printf '%s\n' 'delete table inet toolkit-filter' >>"$batch"
    fi
    if [[ -f "${rollback_dir}/nft.live.present" ]]; then
        cat "${rollback_dir}/nft.live" >>"$batch"
    fi
    if [[ -s "$batch" ]]; then
        nft --check -f "$batch"
        nft -f "$batch"
    fi
    sshd -t
    systemctl reload ssh
    rm -rf -- "$rollback_dir"
}

commit_system() {
    require_root_debian
    prepared_state_matches || die 'prepare state does not match commit'
    systemctl stop toolkit-provision-rollback.timer >/dev/null 2>&1 || true
    systemctl reset-failed toolkit-provision-rollback.service >/dev/null 2>&1 || true
    rm -rf -- "$rollback_dir"
    rm -f -- "$prepared_file" "$helper"
}

case "$mode" in
render-sshd)
    validate_identity
    render_sshd
    ;;
render-nft)
    validate_identity
    render_nft
    ;;
validate-effective-sshd)
    validate_identity
    validate_effective_sshd "$(cat)"
    ;;
prepare)
    validate_identity
    prepare_system
    ;;
activate)
    validate_identity
    activate_system
    ;;
commit)
    validate_identity
    commit_system
    ;;
rollback)
    rollback_system
    ;;
*)
    die 'mode must be prepare, activate, commit, rollback, render-sshd, render-nft or validate-effective-sshd'
    ;;
esac
