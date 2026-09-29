#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
hardener="$root/remote-debian-hardening.sh"
provisioner="$root/provision-server.sh"
picker="$root/lib/ssh-key-picker.sh"
deployer="$root/deploy-installer.sh"
publisher="$root/publish-release-set.sh"
die() {
    printf 'TEST ERROR: %s\n' "$*" >&2
    exit 1
}

bash -n "$picker" "$provisioner" "$deployer" "$publisher" "$hardener" "$0"
"$provisioner" --validate-domain downloads.example.com
if "$provisioner" --validate-domain 'bad/domain' >/dev/null 2>&1; then die 'unsafe serving domain was accepted'; fi
"$provisioner" --validate-public-host 8.8.8.8
if "$provisioner" --validate-public-host 192.168.1.1 >/dev/null 2>&1; then die 'private serving IPv4 was accepted'; fi
grep -Fq 'ADMIN_KEY_DEFAULT="${TOOLKIT_ADMIN_IDENTITY:-${HOME}/.ssh/dynamic}"' "$provisioner" || die 'private-key picker default directory changed'
grep -Fq 'toolkit_select_ssh_private_key()' "$picker" || die 'shared interactive private-key picker is missing'
[[ "$(grep -cF 'key="$(toolkit_select_ssh_private_key "$ADMIN_KEY_DEFAULT")"' "$provisioner")" -eq 2 ]] || die 'private-key picker is not used by both provisioning modes'
if grep -Fq "ask 'Private key file or directory'" "$provisioner"; then die 'a path prompt still hides the private-key selection'; fi
grep -Fq 'TOOLKIT_SSH_IDENTITY_DEFAULT:-${HOME}/.ssh/dynamic' "$deployer" || die 'installer deploy picker default changed'
grep -Fq 'TOOLKIT_SSH_IDENTITY_DEFAULT:-${HOME}/.ssh/dynamic' "$publisher" || die 'release publisher picker default changed'
grep -Fq 'toolkit_select_ssh_private_key "$IDENTITY_DEFAULT"' "$deployer" || die 'installer deploy does not invoke the shared picker'
grep -Fq 'toolkit_select_ssh_private_key "$IDENTITY_DEFAULT"' "$publisher" || die 'release publisher does not invoke the shared picker'
grep -Fq "serving_domain=\"\$(ask 'Public HTTPS DNS name or IPv4' \"\$host\")\"" "$provisioner" || die 'fresh serving public host does not default to the SSH host'
grep -Fq -- '--finish-existing' "$provisioner" || die 'existing hardened host cannot resume serving setup'
grep -Fq 'setup_serving_host' "$provisioner" || die 'serving one-command workflow is missing'
grep -Fq 'snapshot-current-tools.sh first' "$provisioner" || die 'missing release set does not provide an actionable recovery command'
grep -Fq 'TOOLKIT_PUBLIC_BASE_URL="https://${serving_domain}"' "$provisioner" || die 'serving deployment is not wired to its domain'
grep -Fq 'configured_base_line="BASE_URL=\"\${TOOLKIT_BASE_URL:-${PUBLIC_BASE_URL}}\""' "$deployer" || die 'deployed installer does not inherit the selected public host'
grep -Fq 'grep -Fqx "$configured_base_line" "$snapshot"' "$deployer" || die 'configured installer base URL is not verified before deployment'
grep -Fq 'TOOLKIT_MFA_USER=toolkit TOOLKIT_DOWNLOAD_ROOT=/srv/downloads' "$provisioner" || die 'serving MFA defaults are not passed automatically'
grep -Fq 'sudo -n rm -rf --' "$provisioner" || die 'remote MFA staging cleanup is not privileged'
grep -Fq 'printf \"ok\\n\" > /srv/downloads/health.txt' "$provisioner" || die 'serving health endpoint is not created automatically'
grep -Fq 'profile=serving' "$provisioner" || die 'local provisioner is not pinned to serving'
if grep -Eq 'list_projects|load_catalog|projects\.conf' "$provisioner"; then die 'local provisioner still contains VM project selection'; fi

server_sshd="$($hardener render-sshd toolkitadmin 2222 unused serving)"
gui_sshd="$($hardener render-sshd toolkitadmin 2222 unused gui)"
[[ "$server_sshd" == *'AllowTcpForwarding no'* ]] || die 'serving forwarding policy mismatch'
[[ "$gui_sshd" == *'AllowTcpForwarding local'* ]] || die 'GUI local forwarding is missing'
[[ "$gui_sshd" == *'PermitOpen 127.0.0.1:5901 [::1]:5901'* ]] || die 'GUI PermitOpen restriction is missing'
grep -Fq "Match User \$admin" "$hardener" || die "GUI admin Match block is missing"
grep -Fq "Match User download" "$hardener" || die "deploy forwarding boundary is missing"
grep -Fq "Match all" "$hardener" || die "SSH Match context is not reset"
[[ "$server_sshd" == *"AllowUsers toolkitadmin download"* ]] || die "deploy user is not allowed through SSH"
if "$hardener" render-sshd download 2222 unused serving >/dev/null 2>&1; then die "reserved deploy user was accepted as admin"; fi
effective_serving=$'permitrootlogin no
passwordauthentication no
allowusers toolkitadmin
allowusers download
allowtcpforwarding no'
"$hardener" validate-effective-sshd toolkitadmin 2222 unused serving <<<"$effective_serving"
combined_allowusers=$'permitrootlogin no
passwordauthentication no
allowusers toolkitadmin download
allowtcpforwarding no'
if "$hardener" validate-effective-sshd toolkitadmin 2222 unused serving <<<"$combined_allowusers" >/dev/null 2>&1; then
    die 'combined OpenSSH AllowUsers output was accepted'
fi
extra_allowuser=$'permitrootlogin no
passwordauthentication no
allowusers toolkitadmin
allowusers download
allowusers provider
allowtcpforwarding no'
if "$hardener" validate-effective-sshd toolkitadmin 2222 unused serving <<<"$extra_allowuser" >/dev/null 2>&1; then
    die 'unexpected effective AllowUsers entry was accepted'
fi

server_nft="$($hardener render-nft toolkitadmin 2222 unused serving)"
worker_nft="$($hardener render-nft toolkitadmin 2222 unused worker)"
gui_nft="$($hardener render-nft toolkitadmin 2222 unused gui)"
[[ "$server_nft" == *'tcp dport { 80, 443 } accept'* ]] || die 'serving HTTP/HTTPS rules are missing'
[[ "$worker_nft" != *'chain forward'* ]] || die 'worker profile still installs a competing forward base chain'
[[ "$gui_nft" == *'chain forward'* ]] || die 'GUI forward-drop chain is missing'

[[ "$(grep -cF 'apt-get -y full-upgrade' "$hardener")" -eq 1 ]] || die 'full-upgrade must occur exactly once in the hardener'
[[ "$(grep -cF '  install_baseline_settings' "$hardener")" -eq 1 ]] || die 'sysctl baseline must run only in prepare'
grep -Fq 'kernel.unprivileged_bpf_disabled=1' "$hardener" || die 'sysctl baseline was lost'
grep -Fq 'backup_path /etc/nftables.conf nftables.conf' "$hardener" || die 'nftables configuration is missing from rollback'

grep -Fq "trap 'rollback_system' EXIT" "$hardener" || die 'activation failures do not roll back immediately'
grep -Fq 'trap - EXIT' "$hardener" || die 'successful activation does not disarm immediate rollback'

printf '%s\n' 'Provisioning render and serving-only workflow checks passed.'
