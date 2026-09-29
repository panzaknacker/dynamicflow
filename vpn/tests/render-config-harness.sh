#!/usr/bin/env bash
set -Eeuo pipefail

: "${TOOLKIT_VPN_BOOTSTRAP:?}"
: "${TOOLKIT_VPN_TEST_TMP:?}"

# shellcheck source=/dev/null
source "$TOOLKIT_VPN_BOOTSTRAP"

valid_ssh_port 22
valid_ssh_port 65535
! valid_ssh_port 0
! valid_ssh_port 65536
! valid_ssh_port '22;443'

if has_usable_ipv6_default_route <<'EOF_BLOCKING_IPV6_ROUTES'
unreachable default dev lo metric 4278198272 pref medium
blackhole default metric 1024 pref medium
prohibit default metric 1024 pref medium
EOF_BLOCKING_IPV6_ROUTES
then
    printf 'TEST ERROR: blocking-only IPv6 routes were treated as usable\n' >&2
    exit 1
fi
has_usable_ipv6_default_route <<'EOF_USABLE_IPV6_ROUTE'
default via fe80::1 dev ens5 proto ra metric 1024 pref medium
EOF_USABLE_IPV6_ROUTE
has_usable_ipv6_default_route <<'EOF_NHID_IPV6_ROUTE'
default nhid 3253455260 via fe80::41:6ff:fedb:b2cd dev ens5 proto ra metric 100 expires 1689sec pref medium
EOF_NHID_IPV6_ROUTE
has_usable_ipv6_default_route <<'EOF_MIXED_IPV6_ROUTES'
unreachable default dev lo metric 4278198272 pref medium
default via fe80::1 dev ens5 proto ra metric 1024 pref medium
EOF_MIXED_IPV6_ROUTES
if has_usable_ipv6_default_route <<<''; then
    printf 'TEST ERROR: an empty IPv6 route list was treated as usable\n' >&2
    exit 1
fi

ipv6_route_state=2
ipv6_delete_log="$TOOLKIT_VPN_TEST_TMP/ipv6-delete.log"
ipv6_helper_log="$TOOLKIT_VPN_TEST_TMP/ipv6-helper.log"
ip() {
    local IFS=' '

    case "$*" in
    '-6 route show exact ::/0 proto ra')
        if ((ipv6_route_state > 0)); then
            printf 'default nhid %s via fe80::1 dev ens5 proto ra metric 100 pref medium\n' \
                "$((3253455260 + ipv6_route_state))"
        fi
        ;;
    '-6 route del default proto ra')
        printf '%s\n' "$*" >>"$ipv6_delete_log"
        ipv6_route_state=$((ipv6_route_state - 1))
        ;;
    *)
        printf 'TEST ERROR: unexpected mocked ip arguments: %s\n' "$*" >&2
        return 64
        ;;
    esac
}
remove_ipv6_ra_default_routes "$ipv6_helper_log"
[[ "$ipv6_route_state" -eq 0 ]]
[[ "$(wc -l <"$ipv6_delete_log")" -eq 2 ]]
! grep -Fq 'flush' "$ipv6_delete_log"
grep -Fq 'clean delete request' "$ipv6_helper_log"
unset -f ip

SSH_PORTS=(22 2222)
rendered_rules="$TOOLKIT_VPN_TEST_TMP/mullvad-ssh-bypass.nft"
render_ssh_bypass_rules "$rendered_rules"
grep -Fq 'define SSH_PORTS = { 22, 2222 }' "$rendered_rules"
[[ "$(grep -Fc 'ct mark set 0x00000f41 meta mark set 0x6d6f6c65' \
    "$rendered_rules")" -eq 1 ]]
grep -Fq \
    'ct mark 0x00000f41 tcp sport $SSH_PORTS ct state established counter meta mark set 0x6d6f6c65;' \
    "$rendered_rules"
grep -Fq 'type filter hook input priority -100; policy accept;' "$rendered_rules"
grep -Fq 'type route hook output priority -100; policy accept;' "$rendered_rules"
! grep -Eq 'dport[[:space:]]+443|sport[[:space:]]+443' "$rendered_rules"

rendered_boot_service="$TOOLKIT_VPN_TEST_TMP/toolkit-mullvad-ssh-bypass.service"
render_bypass_boot_service "$rendered_boot_service"
grep -Fxq \
    'After=local-fs.target nftables.service mullvad-early-boot-blocking.service' \
    "$rendered_boot_service"
grep -Fxq 'Before=ssh.service sshd.service' "$rendered_boot_service"
grep -Fxq 'ExecStart=/usr/local/libexec/toolkit-mullvad-ssh-bypass-load' \
    "$rendered_boot_service"
grep -Fxq 'WantedBy=multi-user.target' "$rendered_boot_service"

rendered_policy="$TOOLKIT_VPN_TEST_TMP/firefox-policies.json"
render_firefox_policy "$rendered_policy"
jq -e '
  .policies.DNSOverHTTPS == {"Enabled":false,"Locked":true}
  and .policies.Proxy == {"Mode":"none","Locked":true}
  and .policies.Preferences["media.peerconnection.enabled"]
      == {"Value":false,"Status":"locked"}
' "$rendered_policy" >/dev/null

render_rollback_files \
    "$TOOLKIT_VPN_TEST_TMP/rollback" \
    "$TOOLKIT_VPN_TEST_TMP/rollback.service" \
    "$TOOLKIT_VPN_TEST_TMP/rollback.timer"
grep -Fq '/usr/bin/timeout --foreground 20s /usr/bin/mullvad auto-connect set off' \
    "$TOOLKIT_VPN_TEST_TMP/rollback"
grep -Fq '/usr/bin/timeout --foreground 20s /usr/bin/mullvad lockdown-mode set off' \
    "$TOOLKIT_VPN_TEST_TMP/rollback"
grep -Fq '/usr/bin/mullvad disconnect --wait' "$TOOLKIT_VPN_TEST_TMP/rollback"
grep -Fxq 'OnActiveSec=360s' "$TOOLKIT_VPN_TEST_TMP/rollback.timer"
