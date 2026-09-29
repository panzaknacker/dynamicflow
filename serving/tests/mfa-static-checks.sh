#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
setup="$root/setup-caddy-mfa.sh"
installer="$root/install.sh"
service="$root/server/toolkit-auth.service"
jail="$root/server/fail2ban/jail.d/toolkit-mfa.local"
filter="$root/server/fail2ban/filter.d/toolkit-mfa.conf"

die() {
    printf 'TEST ERROR: %s\n' "$*" >&2
    exit 1
}

bash -n "$setup" "$0"
sh -n "$installer"
python3 -m py_compile "$root/server/toolkit_auth.py"
"$setup" --validate-caddy-version v2.11.4
"$setup" --validate-caddy-version v2.12.0
if "$setup" --validate-caddy-version v2.11.3 >/dev/null 2>&1; then die 'outdated Caddy version was accepted'; fi
if "$setup" --validate-caddy-version v2.11.4-rc.1 >/dev/null 2>&1; then die 'prerelease Caddy version was accepted'; fi

caddy_render="$($setup --render-caddy example.test toolkit '\$argon2id\$test' /srv/downloads)"
[[ "$caddy_render" == *'path /_toolkit/auth/token'* ]] || die 'token endpoint is missing'
[[ "$caddy_render" == *'basic_auth argon2id'* ]] || die 'Argon2id first factor is missing'
[[ "$caddy_render" == *'reverse_proxy unix//run/toolkit-auth/auth.sock'* ]] || die 'token broker is not on a Unix socket'
[[ "$caddy_render" == *'forward_auth unix//run/toolkit-auth/auth.sock'* ]] || die 'protected downloads do not use the broker'
[[ "$caddy_render" == *'header_up X-Toolkit-Client-IP {remote_host}'* ]] || die 'Caddy does not overwrite the broker client IP'
[[ "$caddy_render" == *'header_up X-Toolkit-User toolkit'* ]] || die 'Caddy does not pass the authenticated MFA user to the broker'
[[ "$caddy_render" != *'header_up -X-Toolkit-User'* ]] || die 'Caddy deletes the broker user header after setting it'
[[ "$caddy_render" != *'header_up -X-Toolkit-Client-IP'* ]] || die 'Caddy deletes the broker client IP after setting it'
[[ "$caddy_render" == *'output file /var/log/caddy/toolkit-access.json'* ]] || die 'Caddy auth access log is missing'
ip_caddy_render="$($setup --render-caddy 8.8.8.8 toolkit '\$argon2id\$test' /srv/downloads)"
[[ "$ip_caddy_render" == *'issuer acme {'* && "$ip_caddy_render" == *'profile shortlived'* ]] || die 'public IPv4 Caddyfile does not request a trusted short-lived ACME certificate'
[[ "$ip_caddy_render" == *"default_sni 8.8.8.8"* ]] || die 'public IPv4 Caddyfile does not serve clients which omit SNI'
[[ "$caddy_render" != *'default_sni '* ]] || die 'DNS Caddyfile unnecessarily sets a default SNI'
[[ "$caddy_render" != *'profile shortlived'* ]] || die 'DNS Caddyfile unnecessarily forces the IP certificate profile'
grep -Fq 'install -d -m 0750 -o download -g caddy' "$setup" || die 'download root ownership is not provisioned'
grep -Fq 'CADDY_MIN_VERSION=2.11.4' "$setup" || die 'secure Caddy minimum version is not pinned'
grep -Fq 'CADDY_KEY_FINGERPRINT=65760C51EDEA2017CEA2CA15155B6D79CA56EA34' "$setup" || die 'official Caddy repository key is not pinned'
grep -Fq "curl --proto '=https' --tlsv1.2" "$setup" || die 'Caddy repository key download is not HTTPS-restricted'
grep -Fq "http.authentication.hashes.argon2id" "$setup" || die 'Argon2id module compatibility check is missing'
grep -Fq "caddy list-modules 2>/dev/null | grep -Fx 'http.authentication.hashes.argon2id' >/dev/null" "$setup" || die 'Argon2id module check can still fail from grep -q SIGPIPE under pipefail'
! grep -Fq 'print $10; exit' "$setup" || die 'Caddy key fingerprint check can still fail from awk SIGPIPE under pipefail'
preflight_line="$(grep -nF 'preflight_caddy "$domain" "$auth_user" "$download_root"' "$setup")"
preflight_line="${preflight_line%%:*}"
password_line="$(grep -nF 'Password: 1) generate' "$setup")"
password_line="${password_line%%:*}"
[[ "$preflight_line" =~ ^[0-9]+$ && "$password_line" =~ ^[0-9]+$ && "$preflight_line" -lt "$password_line" ]] || die 'Caddy preflight does not run before password enrollment'
credential_preflight_line="$(grep -nF 'preflight_systemd_credentials' "$setup" | tail -n1)"
credential_preflight_line="${credential_preflight_line%%:*}"
[[ "$credential_preflight_line" =~ ^[0-9]+$ && "$credential_preflight_line" -lt "$password_line" ]] || die 'systemd credential preflight does not run before password enrollment'
grep -Fq 'PYTHONPYCACHEPREFIX="$temporary_dir/pycache"' "$setup" || die 'remote source tree can receive root-owned Python cache files'
[[ "$(grep -cF 'caddy fmt --overwrite' "$setup")" -eq 2 ]] || die 'both generated Caddyfiles are not formatted before validation'
grep -Fq 'for attempt in {1..40}' "$setup" || die 'TOTP broker health wait is not bounded'
grep -Fq 'journalctl --no-pager -n 50 -u toolkit-auth.service' "$setup" || die 'TOTP broker failure diagnostics are missing'
broker_start_line="$(grep -nF 'systemctl restart toolkit-auth.service' "$setup")"
broker_start_line="${broker_start_line%%:*}"
broker_wait_line="$(grep -nFx 'wait_for_auth_broker' "$setup")"
broker_wait_line="${broker_wait_line%%:*}"
[[ "$broker_start_line" =~ ^[0-9]+$ && "$broker_wait_line" =~ ^[0-9]+$ && "$broker_start_line" -lt "$broker_wait_line" ]] || die 'TOTP broker health wait does not follow service start'
grep -Fq 'for attempt in {1..80}' "$setup" || die 'Fail2ban readiness wait is not bounded'
grep -Fq 'fail2ban-client ping >/dev/null 2>&1' "$setup" || die 'Fail2ban socket readiness check is missing'
grep -Fq 'journalctl --no-pager -n 50 -u fail2ban.service' "$setup" || die 'Fail2ban failure diagnostics are missing'
fail2ban_restart_line="$(grep -nF 'systemctl restart fail2ban.service' "$setup" | tail -n1)"
fail2ban_restart_line="${fail2ban_restart_line%%:*}"
fail2ban_wait_line="$(grep -nFx 'wait_for_fail2ban' "$setup")"
fail2ban_wait_line="${fail2ban_wait_line%%:*}"
[[ "$fail2ban_restart_line" =~ ^[0-9]+$ && "$fail2ban_wait_line" =~ ^[0-9]+$ && "$fail2ban_restart_line" -lt "$fail2ban_wait_line" ]] || die 'Fail2ban readiness wait does not follow service restart'
! grep -Fq 'systemctl enable --now fail2ban.service' "$setup" || die 'Fail2ban is still started twice before its socket check'

! rg -q -- '--netrc|--netrc-optional' "$installer" || die 'installer still reads persistent netrc credentials'
! rg -q -- '--location' "$installer" || die 'authenticated downloads must not follow redirects'
rg -q 'TOOLKIT_AUTH/TOOLKIT_TOTP environment secrets are disabled' "$installer" || die 'environment secrets are not rejected'
rg -q -- '--data-binary @-' "$installer" || die 'TOTP is not sent via stdin'
! rg -q -- '--retry' <(sed -n '/request_access_token()/,/^}/p' "$installer") || die 'MFA token request must not retry'

grep -Fqx 'maxretry = 3' "$jail" || die 'Fail2ban must ban on the third failure'
grep -Fqx 'port = http,https' "$jail" || die 'MFA ban must not lock out SSH'
grep -Fq '"uri":"/_toolkit/auth/token"' "$filter" || die 'Fail2ban filter does not target token failures'
grep -Fq 'RestrictAddressFamilies=AF_UNIX' "$service" || die 'broker is not restricted to Unix sockets'
grep -Fq 'LoadCredentialEncrypted=' "$service" || die 'TOTP credential is not encrypted at rest'
! grep -Fq -- '--refuse-null' "$setup" || die 'systemd-259-only --refuse-null option is still present'
[[ "$(grep -cF -- '--with-key=host' "$setup")" -eq 2 ]] || die 'credential encryption is not pinned to the systemd host key'
grep -Fq 'systemd-creds decrypt --name=users "$credential_candidate" - >/dev/null' "$setup" || die 'encrypted TOTP credential is not verified by decryption'
grep -Fq 'ProtectSystem=strict' "$service" || die 'broker systemd sandbox is incomplete'

printf '%s\n' 'MFA, Caddy, Fail2ban and systemd static checks passed.'
