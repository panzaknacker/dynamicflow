#!/usr/bin/env bash
set -Eeuo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DOMAIN_DEFAULT="${TOOLKIT_DOMAIN_DEFAULT:-downloads.example.com}"
# the provisioner supplies TOOLKIT_DOMAIN, TOOLKIT_MFA_USER and TOOLKIT_DOWNLOAD_ROOT for one-command setup.
USER_DEFAULT=toolkit
DOWNLOAD_ROOT_DEFAULT=/srv/downloads
CADDYFILE=/etc/caddy/Caddyfile
BROKER_TARGET=/usr/local/libexec/toolkit_auth.py
SERVICE_TARGET=/etc/systemd/system/toolkit-auth.service
CREDENTIAL_TARGET=/etc/credstore.encrypted/toolkit-users.cred
FILTER_TARGET=/etc/fail2ban/filter.d/toolkit-mfa.conf
JAIL_TARGET=/etc/fail2ban/jail.d/toolkit-mfa.local
FAIL2BAN_LOCAL_TARGET=/etc/fail2ban/fail2ban.local
EXPIRY_SCRIPT_TARGET=/usr/local/libexec/toolkit-expire-host
EXPIRY_SERVICE_TARGET=/etc/systemd/system/toolkit-expire.service
EXPIRY_TIMER_TARGET=/etc/systemd/system/toolkit-expire.timer
EXPIRY_DEADLINE_TARGET=/var/lib/toolkit-expiry/deadline.epoch
MAX_LIFETIME_HOURS="${TOOLKIT_MAX_LIFETIME_HOURS:-24}"
ACCESS_LOG=/var/log/caddy/toolkit-access.json
BACKUP_ROOT="/root/toolkit-mfa-backups/$(date -u '+%Y%m%dT%H%M%SZ').$$"
CADDY_KEYRING=/usr/share/keyrings/caddy-stable-archive-keyring.gpg
CADDY_SOURCE_LIST=/etc/apt/sources.list.d/caddy-stable.list
CADDY_KEY_URL=https://dl.cloudsmith.io/public/caddy/stable/gpg.155B6D79CA56EA34.key
CADDY_KEY_FINGERPRINT=65760C51EDEA2017CEA2CA15155B6D79CA56EA34
CADDY_MIN_VERSION=2.11.4

temporary_dir=""
tty_state=""
committed=0
caddy_was_active=0
caddy_was_enabled=0
fail2ban_was_active=0
auth_was_active=0
auth_was_enabled=0
expiry_was_active=0
expiry_was_enabled=0

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

restore_tty() {
    if [[ -n "$tty_state" ]]; then
        stty "$tty_state" </dev/tty >/dev/null 2>&1 || true
        tty_state=""
    fi
}

backup_path() {
    local source="$1" name="$2"
    install -d -m 0700 "$BACKUP_ROOT"
    if [[ -e "$source" ]]; then
        [[ -f "$source" && ! -L "$source" ]] || die "Refusing unsafe existing path: $source"
        cp -a -- "$source" "${BACKUP_ROOT}/${name}"
    else
        : >"${BACKUP_ROOT}/${name}.absent"
    fi
}

restore_path() {
    local target="$1" name="$2"
    if [[ -f "${BACKUP_ROOT}/${name}.absent" ]]; then
        rm -f -- "$target"
    elif [[ -f "${BACKUP_ROOT}/${name}" ]]; then
        install -d -m 0755 "$(dirname "$target")"
        cp -a -- "${BACKUP_ROOT}/${name}" "$target"
    fi
}

rollback() {
    restore_tty
    [[ "$committed" -eq 0 && -d "$BACKUP_ROOT" ]] || return 0
    printf '%s\n' 'MFA activation failed; restoring the previous server configuration.' >&2
    systemctl stop toolkit-auth.service >/dev/null 2>&1 || true
    restore_path "$CADDYFILE" Caddyfile
    restore_path "$BROKER_TARGET" broker
    restore_path "$SERVICE_TARGET" service
    restore_path "$CREDENTIAL_TARGET" credential
    restore_path "$FILTER_TARGET" filter
    restore_path "$JAIL_TARGET" jail
    systemctl stop toolkit-expire.timer >/dev/null 2>&1 || true
    restore_path "$FAIL2BAN_LOCAL_TARGET" fail2ban-local
    restore_path "$EXPIRY_SCRIPT_TARGET" expiry-script
    restore_path "$EXPIRY_SERVICE_TARGET" expiry-service
    restore_path "$EXPIRY_TIMER_TARGET" expiry-timer
    restore_path "$EXPIRY_DEADLINE_TARGET" expiry-deadline
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [[ "$expiry_was_enabled" -eq 1 ]]; then systemctl enable toolkit-expire.timer >/dev/null 2>&1 || true; else systemctl disable toolkit-expire.timer >/dev/null 2>&1 || true; fi
    if [[ "$expiry_was_active" -eq 1 ]]; then systemctl start toolkit-expire.timer >/dev/null 2>&1 || true; fi
    if [[ "$auth_was_active" -eq 1 ]]; then
        systemctl restart toolkit-auth.service >/dev/null 2>&1 || true
    fi
    if [[ "$auth_was_enabled" -eq 1 ]]; then
        systemctl enable toolkit-auth.service >/dev/null 2>&1 || true
    else
        systemctl disable toolkit-auth.service >/dev/null 2>&1 || true
    fi
    if [[ "$caddy_was_active" -eq 1 ]]; then
        systemctl restart caddy.service >/dev/null 2>&1 || true
    else
        systemctl stop caddy.service >/dev/null 2>&1 || true
    fi
    if [[ "$caddy_was_enabled" -eq 1 ]]; then
        systemctl enable caddy.service >/dev/null 2>&1 || true
    else
        systemctl disable caddy.service >/dev/null 2>&1 || true
    fi
    if [[ "$fail2ban_was_active" -eq 1 ]]; then
        systemctl restart fail2ban.service >/dev/null 2>&1 || true
    fi
}

cleanup() {
    local status=$?
    restore_tty
    if [[ "$status" -ne 0 ]]; then
        rollback
    fi
    if [[ -n "$temporary_dir" && -d "$temporary_dir" ]]; then
        rm -rf -- "$temporary_dir"
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM HUP

prompt_value() {
    local question="$1" default_value="$2" value
    printf '%s [%s]: ' "$question" "$default_value" >/dev/tty
    IFS= read -r value </dev/tty
    printf '%s' "${value:-$default_value}"
}

read_hidden() {
    local prompt="$1"
    tty_state="$(stty -g </dev/tty)" || die 'Could not read terminal state.'
    stty -echo </dev/tty || die 'Could not disable terminal echo.'
    printf '%s' "$prompt" >/dev/tty
    if ! IFS= read -r REPLY </dev/tty; then
        restore_tty
        printf '\n' >/dev/tty
        die 'Could not read secret from terminal.'
    fi
    restore_tty
    printf '\n' >/dev/tty
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

validate_user() {
    [[ "$1" =~ ^[A-Za-z0-9._@-]{1,128}$ ]] || die 'Download user contains unsupported characters.'
}

validate_root() {
    [[ "$1" =~ ^/[A-Za-z0-9._/-]+$ && "$1" != / && "$1" != */ && "$1" != *'//'* && "/${1#/}/" != *'/../'* && "/${1#/}/" != *'/./'* ]] || die 'Unsafe download root.'
    if [[ -e "$1" || -L "$1" ]]; then
        [[ -d "$1" && ! -L "$1" ]] || die 'Download root must be a regular directory.'
    fi
}

require_caddy_version() {
    local raw="$1" version major minor patch min_major min_minor min_patch
    version="${raw%% *}"
    version="${version#v}"
    [[ "$version" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ ]] || die "Unrecognized stable Caddy version: $raw"
    IFS=. read -r major minor patch <<<"$version"
    IFS=. read -r min_major min_minor min_patch <<<"$CADDY_MIN_VERSION"
    if ((10#$major < 10#$min_major || (10#$major == 10#$min_major && 10#$minor < 10#$min_minor) || (10#$major == 10#$min_major && 10#$minor == 10#$min_minor && 10#$patch < 10#$min_patch))); then
        die "Caddy $CADDY_MIN_VERSION or newer is required; installed: $version"
    fi
}

install_official_caddy() {
    local key_fingerprint
    apt-get update
    apt-get install -y apt-transport-https ca-certificates curl debian-archive-keyring debian-keyring gnupg
    temporary_dir="$(mktemp -d /run/toolkit-caddy-repo.XXXXXX)"
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location "$CADDY_KEY_URL" >"$temporary_dir/caddy.asc"
    key_fingerprint="$(gpg --show-keys --with-colons --fingerprint "$temporary_dir/caddy.asc" 2>/dev/null | awk -F: '$1 == "fpr" && !found { value=$10; found=1 } END { if (found) print value }')"
    [[ "$key_fingerprint" == "$CADDY_KEY_FINGERPRINT" ]] || die "Official Caddy repository key fingerprint mismatch: ${key_fingerprint:-missing}"
    gpg --batch --yes --dearmor --output "$temporary_dir/caddy.gpg" "$temporary_dir/caddy.asc"
    install -m 0644 "$temporary_dir/caddy.gpg" "$CADDY_KEYRING"
    printf "%s\n" "deb [signed-by=$CADDY_KEYRING] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" >"$temporary_dir/caddy-stable.list"
    install -m 0644 "$temporary_dir/caddy-stable.list" "$CADDY_SOURCE_LIST"
    apt-get update
    apt-get install -y caddy fail2ban openssl python3 qrencode
    require_caddy_version "$(caddy version)"
    caddy list-modules 2>/dev/null | grep -Fx 'http.authentication.hashes.argon2id' >/dev/null || die 'Installed Caddy lacks the Argon2id authentication module.'
    rm -rf -- "$temporary_dir"
    temporary_dir=""
}

preflight_caddy() {
    local domain="$1" auth_user="$2" download_root="$3" probe_hash probe_file
    temporary_dir="$(mktemp -d /run/toolkit-caddy-preflight.XXXXXX)"
    probe_file="$temporary_dir/Caddyfile"
    if ! probe_hash="$(printf "%s\n" "toolkit-caddy-compatibility-probe" | caddy hash-password --algorithm argon2id)"; then
        die 'Installed Caddy cannot generate Argon2id password hashes.'
    fi
    [[ "$probe_hash" =~ ^[$]argon2id[$] ]] || die 'Caddy returned an unexpected password-hash format.'
    render_caddy "$domain" "$auth_user" "$probe_hash" "$download_root" >"$probe_file"
    caddy fmt --overwrite "$probe_file" >/dev/null
    caddy validate --config "$probe_file" --adapter caddyfile
    rm -rf -- "$temporary_dir"
    temporary_dir=""
}

preflight_systemd_credentials() {
    local host_key=/var/lib/systemd/credential.secret
    local probe=toolkit-systemd-credential-preflight
    local plain encrypted decrypted host_key_state
    temporary_dir="$(mktemp -d /run/toolkit-credential-preflight.XXXXXX)"
    plain="$temporary_dir/probe.txt"
    encrypted="$temporary_dir/probe.cred"
    printf '%s' "$probe" >"$plain"
    systemd-creds setup
    [[ -f "$host_key" && ! -L "$host_key" ]] || die 'systemd credential host key is missing or unsafe.'
    host_key_state="$(stat -c '%U:%G:%a' "$host_key")"
    case "$host_key_state" in
    root:root:400 | root:root:600) ;;
    *) die "Unsafe systemd credential host key ownership or mode: $host_key_state" ;;
    esac
    systemd-creds encrypt --with-key=host --name=toolkit-preflight "$plain" "$encrypted"
    decrypted="$(systemd-creds decrypt --name=toolkit-preflight "$encrypted" -)"
    [[ "$decrypted" == "$probe" ]] || die 'systemd credential encryption round-trip failed.'
    rm -rf -- "$temporary_dir"
    temporary_dir=""
}

diagnose_auth_broker() {
    systemctl status --no-pager toolkit-auth.service >&2 || true
    journalctl --no-pager -n 50 -u toolkit-auth.service >&2 || true
}

wait_for_auth_broker() {
    local attempt
    for attempt in {1..40}; do
        if curl --fail --silent --unix-socket /run/toolkit-auth/auth.sock http://localhost/health >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    diagnose_auth_broker
    die 'TOTP broker did not become healthy within ten seconds.'
}

diagnose_fail2ban() {
    systemctl status --no-pager fail2ban.service >&2 || true
    journalctl --no-pager -n 50 -u fail2ban.service >&2 || true
}

wait_for_fail2ban() {
    local attempt
    for attempt in {1..80}; do
        if fail2ban-client ping >/dev/null 2>&1 &&
            fail2ban-client status toolkit-mfa >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    diagnose_fail2ban
    die 'Fail2ban and the toolkit-mfa jail did not become ready within twenty seconds.'
}

render_caddy() {
    local domain="$1" auth_user="$2" auth_hash="$3" download_root="$4"
    if is_public_ipv4 "$domain"; then
        cat <<EOF
{
    default_sni $domain
}

$domain {
    tls {
        issuer acme {
            profile shortlived
        }
    }
EOF
    else
        printf '%s\n' "$domain {"
    fi
    cat <<EOF
    root * "$download_root"
    encode zstd gzip
    log {
        output file $ACCESS_LOG {
            roll_size 10MiB
            roll_keep 2
            roll_keep_for 24h
            roll_interval 1h
        }
        format json
    }
    header {
        X-Content-Type-Options nosniff
        Referrer-Policy no-referrer
        -Server
    }

    @public path /health.txt /install.sh
    @issue_token {
        path /_toolkit/auth/token
        method POST
    }
    @mutable path_regexp mutable ^/tools/(index\.txt|release-set\.tsv|release-set-id\.txt|[A-Za-z0-9._-]+/latest\.txt)$
    @versioned path_regexp versioned ^/tools/[A-Za-z0-9._-]+/v[0-9]+\\.[0-9]+\\.[0-9]+[-+._A-Za-z0-9]*/.+

    handle @public {
        header Cache-Control "no-store"
        file_server
    }

    handle @issue_token {
        header Cache-Control "no-store"
        basic_auth argon2id {
            $auth_user $auth_hash
        }
        reverse_proxy unix//run/toolkit-auth/auth.sock {
            header_up -Authorization
            header_up X-Toolkit-User $auth_user
            header_up X-Toolkit-Client-IP {remote_host}
        }
    }

    handle /tools/* {
        route {
            forward_auth unix//run/toolkit-auth/auth.sock {
                uri /verify
                header_up X-Toolkit-Client-IP {remote_host}
            }
            header @mutable Cache-Control "private, no-store"
            header @versioned Cache-Control "private, max-age=31536000, immutable"
            file_server
        }
    }

    handle {
        respond "Not found" 404
    }
}
EOF
}

if [[ "${1:-}" == --validate-caddy-version ]]; then
    [[ "$#" -eq 2 ]] || die 'Usage: setup-caddy-mfa.sh --validate-caddy-version VERSION'
    require_caddy_version "$2"
    committed=1
    exit 0
fi

if [[ "${1:-}" == --render-caddy ]]; then
    [[ "$#" -eq 5 ]] || die 'Usage: setup-caddy-mfa.sh --render-caddy PUBLIC_HOST USER HASH DOWNLOAD_ROOT'
    render_caddy "$2" "$3" "$4" "$5"
    committed=1
    exit 0
fi

[[ "$(id -u)" -eq 0 ]] || die 'Run with sudo or as root.'
[[ -r /dev/tty && -w /dev/tty ]] || die 'MFA enrollment requires a real terminal.'
systemctl is-active --quiet caddy.service && caddy_was_active=1 || true
systemctl is-enabled --quiet caddy.service && caddy_was_enabled=1 || true
systemctl is-active --quiet fail2ban.service && fail2ban_was_active=1 || true
systemctl is-active --quiet toolkit-auth.service && auth_was_active=1 || true
systemctl is-enabled --quiet toolkit-auth.service && auth_was_enabled=1 || true
systemctl is-active --quiet toolkit-expire.timer && expiry_was_active=1 || true
systemctl is-enabled --quiet toolkit-expire.timer && expiry_was_enabled=1 || true
[[ "$MAX_LIFETIME_HOURS" =~ ^[1-9][0-9]*$ ]] && ((MAX_LIFETIME_HOURS <= 168)) || die 'TOOLKIT_MAX_LIFETIME_HOURS must be between 1 and 168.'
export DEBIAN_FRONTEND=noninteractive
install_official_caddy
if [[ "$caddy_was_active" -eq 0 ]]; then
    systemctl stop caddy.service >/dev/null 2>&1 || true
fi
for command in caddy curl fail2ban-client gpg journalctl openssl python3 qrencode sleep stat sudo systemctl systemd-creds; do
    command -v "$command" >/dev/null 2>&1 || die "Missing required command: $command"
done
[[ -f "$HERE/server/toolkit_auth.py" && ! -L "$HERE/server/toolkit_auth.py" ]] || die 'Missing TOTP broker source.'
[[ -f "$HERE/server/toolkit-auth.service" && ! -L "$HERE/server/toolkit-auth.service" ]] || die 'Missing broker service unit.'

domain="${TOOLKIT_DOMAIN:-}"
auth_user="${TOOLKIT_MFA_USER:-}"
download_root="${TOOLKIT_DOWNLOAD_ROOT:-}"
[[ -n "$domain" ]] || domain="$(prompt_value 'Public HTTPS DNS name or IPv4' "$DOMAIN_DEFAULT")"
[[ -n "$auth_user" ]] || auth_user="$(prompt_value 'MFA login user' "$USER_DEFAULT")"
[[ -n "$download_root" ]] || download_root="$(prompt_value 'Download root' "$DOWNLOAD_ROOT_DEFAULT")"
validate_public_host "$domain"
validate_user "$auth_user"
validate_root "$download_root"
id download >/dev/null 2>&1 || die 'The provisioned download deploy user is missing.'
getent group caddy >/dev/null || die 'The caddy system group is missing.'
if [[ ! -e "$download_root" && ! -L "$download_root" ]]; then
    install -d -m 0750 -o download -g caddy "$download_root"
fi
sudo -u download test -w "$download_root" || die 'Download root is not writable by deploy user download.'
sudo -u caddy test -r "$download_root" || die 'Download root is not readable by caddy.'
canonical_download_root="$(cd "$download_root" && pwd -P)"
[[ "$canonical_download_root" == "$download_root" ]] || die 'Download root contains symlinked or non-canonical components.'
install -d -m 0750 -o caddy -g caddy /var/log/caddy
preflight_caddy "$domain" "$auth_user" "$download_root"
preflight_systemd_credentials

printf '%s\n' 'Password: 1) generate 192-bit password (recommended), 2) enter your own' >/dev/tty
password_mode="$(prompt_value Selection 1)"
case "$password_mode" in
1)
    password="$(openssl rand -hex 24)"
    printf '\nGenerated download password (shown once):\n%s\n' "$password" >/dev/tty
    printf '%s' 'Store it in your password manager, then press Enter. ' >/dev/tty
    IFS= read -r _ack </dev/tty
    ;;
2)
    read_hidden 'Download password (minimum 16 characters): '
    password="$REPLY"
    read_hidden 'Repeat download password: '
    [[ "$password" == "$REPLY" ]] || die 'Passwords do not match.'
    ((${#password} >= 16)) || die 'Password must contain at least 16 characters.'
    ;;
*) die 'Selection must be 1 or 2.' ;;
esac
if printf '%s' "$password" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    die 'Password must not contain control characters.'
fi
auth_hash="$(printf '%s\n' "$password" | caddy hash-password --algorithm argon2id)"
password=''
[[ "$auth_hash" == \$argon2id\$* ]] || die 'Caddy did not return an Argon2id hash.'

totp_secret="$(python3 -c 'import base64,secrets; print(base64.b32encode(secrets.token_bytes(20)).decode().rstrip("="))')"
otpauth_uri="otpauth://totp/Toolkit:${auth_user}@${domain}?secret=${totp_secret}&issuer=Toolkit&algorithm=SHA1&digits=6&period=30"
printf '\nTOTP enrollment for %s@%s\n' "$auth_user" "$domain" >/dev/tty
printf '%s' "$otpauth_uri" | qrencode -t ANSIUTF8 >/dev/tty
printf '\nManual Base32 copy/paste secret:\n%s\n\n' "$totp_secret" >/dev/tty

verified=0
for _attempt in 1 2 3; do
    read_hidden 'Current 6-digit TOTP code: '
    if [[ "$REPLY" =~ ^[0-9]{6}$ ]] &&
        printf '%s\n%s\n' "$totp_secret" "$REPLY" | python3 "$HERE/server/toolkit_auth.py" verify-stdin-totp; then
        verified=1
        break
    fi
    printf '%s\n' 'Code did not verify; check server time and the authenticator entry.' >/dev/tty
done
[[ "$verified" -eq 1 ]] || die 'TOTP enrollment was not verified.'
REPLY=''

temporary_dir="$(mktemp -d /run/toolkit-mfa.XXXXXX)"
caddy_candidate="${temporary_dir}/Caddyfile"
credential_plain="${temporary_dir}/users.json"
credential_candidate="${temporary_dir}/users.cred"
render_caddy "$domain" "$auth_user" "$auth_hash" "$download_root" >"$caddy_candidate"
caddy fmt --overwrite "$caddy_candidate" >/dev/null
printf '{"version":1,"users":{"%s":{"secret_base32":"%s"}}}\n' "$auth_user" "$totp_secret" >"$credential_plain"
totp_secret=''
otpauth_uri=''
chmod 0600 "$credential_plain" "$caddy_candidate"
PYTHONPYCACHEPREFIX="$temporary_dir/pycache" python3 -m py_compile "$HERE/server/toolkit_auth.py"
caddy validate --config "$caddy_candidate" --adapter caddyfile

systemd-creds encrypt --with-key=host --name=users "$credential_plain" "$credential_candidate"
systemd-creds decrypt --name=users "$credential_candidate" - >/dev/null
rm -f -- "$credential_plain"

backup_path "$CADDYFILE" Caddyfile
backup_path "$BROKER_TARGET" broker
backup_path "$SERVICE_TARGET" service
backup_path "$CREDENTIAL_TARGET" credential
backup_path "$FILTER_TARGET" filter
backup_path "$JAIL_TARGET" jail
backup_path "$FAIL2BAN_LOCAL_TARGET" fail2ban-local
backup_path "$EXPIRY_SCRIPT_TARGET" expiry-script
backup_path "$EXPIRY_SERVICE_TARGET" expiry-service
backup_path "$EXPIRY_TIMER_TARGET" expiry-timer
backup_path "$EXPIRY_DEADLINE_TARGET" expiry-deadline

getent group caddy >/dev/null || die 'The caddy system group is missing.'
id toolkit-auth >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin toolkit-auth
install -d -m 0755 /usr/local/libexec /etc/systemd/system /etc/fail2ban/filter.d /etc/fail2ban/jail.d /var/lib/toolkit-expiry
install -d -m 0700 /etc/credstore.encrypted
install -d -m 0750 -o caddy -g caddy /var/log/caddy
touch "$ACCESS_LOG"
chown caddy:caddy "$ACCESS_LOG"
chmod 0640 "$ACCESS_LOG"
install -m 0755 "$HERE/server/toolkit_auth.py" "$BROKER_TARGET"
install -m 0644 "$HERE/server/toolkit-auth.service" "$SERVICE_TARGET"
install -m 0600 "$credential_candidate" "$CREDENTIAL_TARGET"
install -m 0644 "$HERE/server/fail2ban/filter.d/toolkit-mfa.conf" "$FILTER_TARGET"
install -m 0644 "$HERE/server/fail2ban/jail.d/toolkit-mfa.local" "$JAIL_TARGET"
install -m 0644 "$HERE/server/fail2ban/fail2ban.local" "$FAIL2BAN_LOCAL_TARGET"
install -m 0755 "$HERE/server/toolkit-expire-host" "$EXPIRY_SCRIPT_TARGET"
install -m 0644 "$HERE/server/toolkit-expire.service" "$EXPIRY_SERVICE_TARGET"
install -m 0644 "$HERE/server/toolkit-expire.timer" "$EXPIRY_TIMER_TARGET"
if [[ ! -e "$EXPIRY_DEADLINE_TARGET" ]]; then printf '%s\n' "$(($(date -u '+%s') + MAX_LIFETIME_HOURS * 3600))" >"$EXPIRY_DEADLINE_TARGET"; fi
chown root:root "$EXPIRY_DEADLINE_TARGET"
chmod 0600 "$EXPIRY_DEADLINE_TARGET"
install -o root -g caddy -m 0640 "$caddy_candidate" "$CADDYFILE"

systemctl daemon-reload
systemctl enable --now toolkit-expire.timer
systemctl enable toolkit-auth.service
systemctl restart toolkit-auth.service
wait_for_auth_broker
systemctl enable --now caddy.service
systemctl reload caddy.service
systemctl is-active --quiet caddy.service
fail2ban-client -t
systemctl enable fail2ban.service
systemctl restart fail2ban.service
wait_for_fail2ban

committed=1
cat >/dev/tty <<EOF

MFA is active.

Public:
  https://${domain}/health.txt
  https://${domain}/install.sh

Protected downloads now require the download password plus a fresh TOTP once
per installer invocation. The resulting token is bound to the source IP and
expires after ten minutes. The third failed MFA attempt within ten minutes is
banned for one hour; repeated bans grow up to one week. SSH remains reachable
for administrative unban operations.

The TOTP secret is stored as an encrypted systemd credential. The password is
stored only as an Argon2id hash. QR/Base32 and generated password were displayed
only during this enrollment.
EOF
