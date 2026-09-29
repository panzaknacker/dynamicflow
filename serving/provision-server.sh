#!/usr/bin/env bash
set -Eeuo pipefail

IFS=$'\n\t'
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SSH_KEY_PICKER="${HERE}/lib/ssh-key-picker.sh"
HARDEN="${TOOLKIT_HARDEN_SCRIPT:-${HERE}/remote-debian-hardening.sh}"
MFA_SETUP="${TOOLKIT_MFA_SETUP_SCRIPT:-${HERE}/setup-caddy-mfa.sh}"
MFA_SERVER_DIR="${TOOLKIT_MFA_SERVER_DIR:-${HERE}/server}"
DEPLOY_INSTALLER="${TOOLKIT_DEPLOY_INSTALLER:-${HERE}/deploy-installer.sh}"
PUBLISH_RELEASE_SET="${TOOLKIT_PUBLISH_RELEASE_SET:-${HERE}/publish-release-set.sh}"
ADMIN_KEY_DEFAULT="${TOOLKIT_ADMIN_IDENTITY:-${HOME}/.ssh/dynamic}"

[[ -f "$SSH_KEY_PICKER" && ! -L "$SSH_KEY_PICKER" ]] || {
    printf 'ERROR: Unsafe or missing SSH key picker: %s\n' "$SSH_KEY_PICKER" >&2
    exit 1
}
# shellcheck source=lib/ssh-key-picker.sh
source "$SSH_KEY_PICKER"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

ask() {
    local value
    printf '%s [%s]: ' "$1" "$2" >&2
    read -r value
    printf '%s' "${value:-$2}"
}

confirm() {
    local value
    printf '%s [y/N]: ' "$1" >&2
    read -r value
    [[ "$value" =~ ^([yY]|yes|YES)$ ]]
}

is_ip_address() {
    python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$1" >/dev/null 2>&1
}

is_public_ipv4() {
    python3 -c 'import ipaddress,sys; value=ipaddress.ip_address(sys.argv[1]); raise SystemExit(0 if value.version == 4 and value.is_global else 1)' "$1" >/dev/null 2>&1
}

validate_public_host() {
    if is_ip_address "$1"; then
        is_public_ipv4 "$1" || die 'Public HTTPS IP must be a globally routable IPv4 address.'
        return 0
    fi
    [[ "$1" =~ ^[0-9.]+$ ]] && die 'Invalid IPv4 address.'
    [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?[.])+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || die 'Public HTTPS host must be a DNS name or globally routable IPv4 address.'
}

validate_serving_assets() {
    [[ -f "$MFA_SETUP" && ! -L "$MFA_SETUP" ]] || die "Unsafe or missing MFA setup: $MFA_SETUP"
    [[ -d "$MFA_SERVER_DIR" && ! -L "$MFA_SERVER_DIR" ]] || die "Unsafe or missing MFA server directory: $MFA_SERVER_DIR"
    [[ -f "$DEPLOY_INSTALLER" && ! -L "$DEPLOY_INSTALLER" ]] || die "Unsafe or missing installer deployer: $DEPLOY_INSTALLER"
    [[ -f "$PUBLISH_RELEASE_SET" && ! -L "$PUBLISH_RELEASE_SET" ]] || die "Unsafe or missing release-set publisher: $PUBLISH_RELEASE_SET"
    [[ -e "$HERE/current" || -L "$HERE/current" ]] ||
        die "No sealed release set exists at $HERE/current. Run $HERE/snapshot-current-tools.sh first."
    "$HERE/verify-release-set.sh" "$HERE/current" >/dev/null
}

setup_serving_host() {
    local remote_setup
    ensure_deploy_identity
    remote_setup="/tmp/toolkit-serving-$RANDOM-$RANDOM"
    printf '%s\n' 'Installing Caddy, MFA, Fail2ban, health endpoint and public installer.'
    ssh "${new[@]}" -- "$admin@$host" "umask 077; mkdir '$remote_setup'"
    scp "${copy_new[@]}" -- "$MFA_SETUP" "$admin@$host:$remote_setup/setup-caddy-mfa.sh"
    scp "${copy_new[@]}" -r -- "$MFA_SERVER_DIR" "$admin@$host:$remote_setup/server"
    ssh "${new[@]}" -tt -- "$admin@$host" \
        "cd '$remote_setup'; sudo -n env TOOLKIT_DOMAIN=$serving_domain TOOLKIT_MFA_USER=toolkit TOOLKIT_DOWNLOAD_ROOT=/srv/downloads bash ./setup-caddy-mfa.sh; status=\$?; cd /; sudo -n rm -rf -- '$remote_setup'; exit \$status"
    ssh "${deploy_ssh[@]}" -- "download@$host" \
        "umask 022; printf \"ok\\n\" > /srv/downloads/health.txt"
    TOOLKIT_SSH_HOST="$host" \
        TOOLKIT_SSH_PORT="$port" \
        TOOLKIT_SSH_IDENTITY="$deploy_key" \
        TOOLKIT_DEPLOY_USER=download \
        TOOLKIT_PUBLIC_BASE_URL="https://${serving_domain}" \
        "$DEPLOY_INSTALLER"
    if ((publish_release_set)); then
        TOOLKIT_RELEASE_SET="$HERE/current" \
            TOOLKIT_SSH_HOST="$host" \
            TOOLKIT_SSH_PORT="$port" \
            TOOLKIT_SSH_IDENTITY="$deploy_key" \
            TOOLKIT_DEPLOY_USER=download \
            TOOLKIT_PUBLIC_BASE_URL="https://${serving_domain}" \
            "$PUBLISH_RELEASE_SET"
    else
        printf "%s\n" "Release set unchanged (MFA reset only)."
    fi
    printf 'SERVING_READY: https://%s/install.sh\n' "$serving_domain"
}

mode=fresh
publish_release_set=1
ensure_deploy_identity() {
    local deploy_pub backup_name
    deploy_key="${TOOLKIT_DEPLOY_IDENTITY:-$HOME/.ssh/toolkit-serving-download}"
    install -d -m 0700 "$(dirname "$deploy_key")"
    if [[ ! -e "$deploy_key" ]]; then
        ssh-keygen -q -t ed25519 -N '' -C toolkit-serving-download -f "$deploy_key"
    fi
    [[ -f "$deploy_key" && ! -L "$deploy_key" ]] || die "Unsafe deploy key: $deploy_key"
    chmod 0600 "$deploy_key"
    deploy_pub="$(ssh-keygen -y -f "$deploy_key")"
    [[ "$deploy_pub" == ssh-ed25519\ * ]] || die 'Deploy key must be Ed25519.'

    backup_name="/root/download-authorized-keys.provision.$$"
    ssh "${new[@]}" -- "$admin@$host" "sudo -n cp -a /home/download/.ssh/authorized_keys '$backup_name'"
    printf 'restrict %s\n' "$deploy_pub" |
        ssh "${new[@]}" -- "$admin@$host" "set -eu; candidate=\$(mktemp); cat >\"\$candidate\"; grep -Eq '^restrict ssh-ed25519 [A-Za-z0-9+/=]+( .*)?$' \"\$candidate\"; sudo -n install -o download -g download -m 0600 \"\$candidate\" /home/download/.ssh/authorized_keys; rm -f \"\$candidate\""

    deploy_ssh=(
        -o StrictHostKeyChecking=accept-new
        -o IdentitiesOnly=yes
        -o PasswordAuthentication=no
        -o KbdInteractiveAuthentication=no
        -o PreferredAuthentications=publickey
        -o ClearAllForwardings=yes
        -o ForwardAgent=no
        -i "$deploy_key"
        -p "$port"
    )
    if ! ssh "${deploy_ssh[@]}" -- "download@$host" true; then
        ssh "${new[@]}" -- "$admin@$host" "sudo -n cp -a '$backup_name' /home/download/.ssh/authorized_keys; sudo -n chown download:download /home/download/.ssh/authorized_keys"
        die 'Separate download deploy key failed; previous key was restored.'
    fi
    ssh "${new[@]}" -- "$admin@$host" "sudo -n rm -f '$backup_name'"
}
finish_host=""

case "${1:-}" in
--validate-domain | --validate-public-host)
    [[ "$#" -eq 2 ]] || die 'Usage: ./provision-server.sh --validate-public-host PUBLIC_HOST'
    validate_public_host "$2"
    exit
    ;;
--reset-mfa)
    [[ "$#" -eq 2 ]] || die 'Usage: ./provision-server.sh --reset-mfa PUBLIC_IPV4_OR_DNS'
    mode=reset
    finish_host="$2"
    publish_release_set=0
    ;;
--finish-existing)
    [[ "$#" -eq 2 ]] || die 'Usage: ./provision-server.sh --finish-existing PUBLIC_IPV4_OR_DNS'
    mode=finish
    finish_host="$2"
    ;;
-h | --help)
    printf '%s\n' 'Usage: ./provision-server.sh [--reset-mfa PUBLIC_IPV4_OR_DNS] [--finish-existing PUBLIC_IPV4_OR_DNS] [--validate-public-host PUBLIC_HOST]'
    exit
    ;;
'') ;;
*) die "Unknown option: $1" ;;
esac

[[ -t 0 && -t 1 ]] || die 'Interactive terminal required.'
[[ -f "$HARDEN" && ! -L "$HARDEN" ]] || die "Unsafe or missing hardening script: $HARDEN"
if [[ "$mode" == finish || "$mode" == reset ]]; then
    host="$(ask 'Existing server SSH IP/DNS' "$finish_host")"
    admin="$(ask 'Existing admin' toolkitadmin)"
    port="$(ask 'Permanent SSH port' 22)"
    serving_domain="$(ask 'Public HTTPS DNS name or IPv4' "$finish_host")"
    validate_public_host "$serving_domain"
    validate_serving_assets

    key="$(toolkit_select_ssh_private_key "$ADMIN_KEY_DEFAULT")"

    [[ "$host" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]] || die 'Invalid host.'
    [[ "$admin" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die 'Invalid admin user.'
    [[ "$port" =~ ^[0-9]+$ ]] && ((10#$port > 0 && 10#$port < 65536)) || die 'Invalid port.'
    [[ -f "$key" && ! -L "$key" ]] || die 'Unsafe or missing private key.'
    chmod 0600 "$key"

    common_ssh=(-o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o PreferredAuthentications=publickey -o ClearAllForwardings=yes -o ForwardAgent=no -i "$key")
    new=("${common_ssh[@]}" -p "$port")
    copy_new=("${common_ssh[@]}" -P "$port")

    printf '\nReconfiguring MFA/HTTPS on %s@%s:%s for https://%s\n' "$admin" "$host" "$port" "$serving_domain"
    confirm 'Existing hardened server reachable; replace its MFA enrollment?' || die 'Cancelled.'
    ssh "${new[@]}" -- "$admin@$host" 'sudo -n true'
    setup_serving_host
    printf 'Done: ssh -i %q -p %q %q@%q\n' "$key" "$port" "$admin" "$host"
    exit
fi

host="$(ask 'Server IP/DNS' '')"
old_user="$(ask 'Provider SSH user' root)"
old_port="$(ask 'Initial SSH port' 22)"
admin="$(ask 'New admin' toolkitadmin)"
port="$(ask 'Permanent SSH port' 22)"
profile=serving
serving_domain="$(ask 'Public HTTPS DNS name or IPv4' "$host")"
validate_public_host "$serving_domain"
validate_serving_assets

key="$(toolkit_select_ssh_private_key "$ADMIN_KEY_DEFAULT")"

[[ "$host" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]] || die 'Invalid host.'
[[ "$old_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ && "$admin" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die 'Invalid user.'
for checked_port in "$old_port" "$port"; do
    [[ "$checked_port" =~ ^[0-9]+$ ]] && ((10#$checked_port > 0 && 10#$checked_port < 65536)) || die 'Invalid port.'
done
[[ -f "$key" && ! -L "$key" ]] || die 'Unsafe or missing private key.'
chmod 0600 "$key"
pub="$(ssh-keygen -y -f "$key")"
[[ "$pub" == ssh-*\ * ]] || die 'Invalid public key.'

common_ssh=(-o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o PreferredAuthentications=publickey -o ClearAllForwardings=yes -o ForwardAgent=no -i "$key")
old=("${common_ssh[@]}" -p "$old_port")
admin_old=("${common_ssh[@]}" -p "$old_port")
new=("${common_ssh[@]}" -p "$port")
copy=("${common_ssh[@]}" -P "$old_port")
copy_new=("${common_ssh[@]}" -P "$port")
tmp="/tmp/toolkit-$RANDOM-$RANDOM"

printf '\n%s@%s:%s -> %s@%s:%s  profile=%s\n' "$old_user" "$host" "$old_port" "$admin" "$host" "$port" "$profile"
confirm 'Provider console open; start?' || die 'Cancelled.'

ssh "${old[@]}" -- "$old_user@$host" 'set -eu; . /etc/os-release; [ "$ID" = debian ] && [ "$VERSION_ID" = 13 ]'
ssh "${old[@]}" -- "$old_user@$host" "umask 077; mkdir '$tmp'"
scp "${copy[@]}" -- "$HARDEN" "$old_user@$host:$tmp/hardening.sh"
printf '%s\n' "$pub" | ssh "${old[@]}" -- "$old_user@$host" "umask 077; cat >'$tmp/admin.pub'"

if [[ "$old_user" == root ]]; then
    sudo_prefix=''
else
    sudo_prefix='sudo '
fi
ssh "${old[@]}" -tt -- "$old_user@$host" "${sudo_prefix}bash '$tmp/hardening.sh' prepare '$admin' '$port' '$tmp/admin.pub' '$profile'"
ssh "${admin_old[@]}" -- "$admin@$host" 'sudo -n true'
ssh "${admin_old[@]}" -tt -- "$admin@$host" "sudo -n bash '$tmp/hardening.sh' activate '$admin' '$port' '$tmp/admin.pub' '$profile'"

printf '%s\n' 'Testing a fresh connection before cancelling the five-minute rollback timer.'
ssh "${new[@]}" -- "$admin@$host" 'sudo -n true'
ssh "${new[@]}" -- "$admin@$host" "sudo -n bash '$tmp/hardening.sh' commit '$admin' '$port' '$tmp/admin.pub' '$profile'; sudo -n rm -rf '$tmp'; echo HARDENING_OK"

setup_serving_host

printf 'Done: ssh -i %q -p %q %q@%q\n' "$key" "$port" "$admin" "$host"
