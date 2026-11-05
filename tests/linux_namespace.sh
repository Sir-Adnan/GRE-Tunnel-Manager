#!/usr/bin/env bash
# All packet/filter tests run in a private network namespace. Never use the host ruleset.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ${GTM_INSIDE_TEST_NS:-0} != 1 ]]; then
    exec unshare -n env GTM_INSIDE_TEST_NS=1 bash "$0"
fi
source ./gre.sh
gtm_paths
test_dir=$(mktemp -d)
cleanup() {
    local status=$?
    if ((status)); then for log in "$test_dir"/*.log; do [[ ! -f $log ]] || tail -20 "$log" >&2; done; fi
    for child in "${routing_pid:-}" "${realm_peer_pid:-}" "${health_pid:-}" "${held_pid:-}" "${proxy_server_pid:-}" "${capture_pid:-}" "${rathole_client_pid:-}" "${rathole_server_pid:-}" "${gateway_pid:-}" "${relay_pid:-}" "${frpc_pid:-}" "${frps_pid:-}" "${server_pid:-}" "${client_ns:-}" "${backend_ns:-}"; do [[ -z $child ]] || kill "$child" 2>/dev/null || true; done
    # mktemp above creates this absolute private root; never follow symlinks out.
    [[ $test_dir == /tmp/tmp.* && -d $test_dir ]] || return 1
    find "$test_dir" -mindepth 1 -depth -delete; rmdir "$test_dir"
}
trap cleanup EXIT
GTM_RUN_DIR=$test_dir
mkdir -m 700 "$GTM_RUN_DIR/haproxy"

GTM_RECORDS=($'F000001\tWeighted forward\tnftables\tboth\t192.0.2.10\t443\trandom\t1\tmasquerade\tany\t203.0.113.20:443@2,203.0.113.21:8443@1\t1')
gtm_nft_render > "$test_dir/rules.nft"
nft -c -f "$test_dir/rules.nft"
nft -f "$test_dir/rules.nft"
nft list table inet gre_manager > "$test_dir/first"
nft -f "$test_dir/rules.nft"
nft list table inet gre_manager > "$test_dir/second"
cmp "$test_dir/first" "$test_dir/second"
# IPv6 grammar and actual kernel acceptance, including changed destination ports.
GTM_RECORDS=($'F000001\tIPv6 forward\tnftables\tboth\t2001:db8::1\t51820\trandom\t1\tmasquerade\tany\t[2001:db8::2]:51820@1,[2001:db8::3]:51821@2\t1')
gtm_nft_render > "$test_dir/rules.nft"
nft -c -f "$test_dir/rules.nft"
nft -f "$test_dir/rules.nft"
# Weighted incremental and stable source-IP selectors, accepted by the kernel.
for selector in roundrobin source; do
    GTM_RECORDS=("${GTM_RECORDS[0]/$'\trandom\t'/$'\t'${selector}$'\t'}")
    gtm_nft_render > "$test_dir/rules.nft"
    nft -c -f "$test_dir/rules.nft"
    nft -f "$test_dir/rules.nft"
    GTM_RECORDS=("${GTM_RECORDS[0]/$'\t'${selector}$'\t'/$'\trandom\t'}")
done
GTM_RECORDS=()
gtm_nft_render > "$test_dir/rules.nft"
nft -f "$test_dir/rules.nft"
if nft list table inet gre_manager | grep -q 'gtm-F000001'; then printf 'Unexpected success: %s\n' 'nft list table inet gre_manager  grep -q gtm-F000001' >&2; exit 1; fi

# Real request/reply paths, without touching host interfaces or /run/netns.
unshare -n sleep 120 & client_ns=$!
unshare -n sleep 120 & backend_ns=$!
sleep 0.2
ip link set lo up
ip link add tm_in type veth peer name tm_client
ip link set tm_client netns "$client_ns"
ip addr add 192.0.2.10/24 dev tm_in
ip link set tm_in up
nsenter -t "$client_ns" -n ip addr add 192.0.2.2/24 dev tm_client
nsenter -t "$client_ns" -n ip link set tm_client up
nsenter -t "$client_ns" -n ip route add default via 192.0.2.10
ip link add tm_out type veth peer name tm_backend
ip link set tm_backend netns "$backend_ns"
ip addr add 203.0.113.1/24 dev tm_out
ip link set tm_out up
nsenter -t "$backend_ns" -n ip addr add 203.0.113.20/24 dev tm_backend
nsenter -t "$backend_ns" -n ip link set tm_backend up
nsenter -t "$backend_ns" -n ip link set lo up
nsenter -t "$backend_ns" -n ip route add default via 203.0.113.1
sysctl -qw net.ipv4.ip_forward=1
nsenter -t "$backend_ns" -n python3 tests/packet_probe.py server & server_pid=$!
sleep 0.2
GTM_RECORDS=($'F000002\tPacket test\tnftables\tboth\t192.0.2.10\t28443\tsingle\t1\tmasquerade\ttm_in\t203.0.113.20:28001@1\t1')
gtm_preflight
gtm_nft_render | nft -f -
nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28443
# Optional Go panel counters: both directions count actual forwarded TCP/UDP
# packets. Removing the separate accounting table must leave forwarding intact.
if [[ -n ${GTM_PANEL_TEST_BINARY:-} && -x $GTM_PANEL_TEST_BINARY ]]; then
    printf '%s\n' "${GTM_RECORDS[@]}" > "$test_dir/panel-state.tsv"
    "$GTM_PANEL_TEST_BINARY" metrics-plan --state-file "$test_dir/panel-state.tsv" > "$test_dir/panel-metrics.nft"
    nft -c -f "$test_dir/panel-metrics.nft"
    nft -f "$test_dir/panel-metrics.nft"
    nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28443
    nft -j list table inet gtm_panel_metrics > "$test_dir/panel-counters.json"
    python3 - "$test_dir/panel-counters.json" <<'PY'
import json, sys
counters={entry['counter']['name']:entry['counter']['bytes'] for entry in json.load(open(sys.argv[1]))['nftables'] if 'counter' in entry}
assert counters['F000002_rx'] > 0 and counters['F000002_tx'] > 0, counters
PY
    nft delete table inet gtm_panel_metrics
    nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28443
    printf 'PASS: Go panel counters measure both directions without replacing forwarding rules.\n'
fi
# Rejected candidates must leave already-active forwarding intact.
nft -s list table inet gre_manager > "$test_dir/before-preflight"
saved_record=${GTM_RECORDS[0]}
GTM_RECORDS=("${saved_record/192.0.2.10/192.0.2.99}")
if gtm_preflight; then printf 'Invalid local bind passed preflight\n' >&2; exit 1; fi
nft -s list table inet gre_manager > "$test_dir/after-preflight"
cmp "$test_dir/before-preflight" "$test_dir/after-preflight"
GTM_RECORDS=("$saved_record")
# A native syntax-check failure must also preserve the active table.
if (gtm_nft_render() { printf 'invalid nft syntax\n'; }; gtm_preflight); then
    printf 'Invalid native config passed preflight\n' >&2; exit 1
fi
nft -s list table inet gre_manager > "$test_dir/after-syntax-preflight"
cmp "$test_dir/before-preflight" "$test_dir/after-syntax-preflight"
nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28443
GTM_RECORDS=()
gtm_nft_render | nft -f -
if nft list table inet gre_manager >/dev/null 2>&1; then printf 'Owned table survived without records\n' >&2; exit 1; fi

# Additional IPs: an all-addresses kernel forward accepts on every local IP,
# while an explicit bind still matches only its own address.
ip addr add 192.0.2.11/24 dev tm_in
GTM_RECORDS=($'F000004\tAll addresses\tnftables\tboth\t0.0.0.0\t28446\tsingle\t1\tmasquerade\ttm_in\t203.0.113.20:28001@1\t1'
             $'F000005\tOne address\tnftables\ttcp\t192.0.2.11\t28447\tsingle\t1\tmasquerade\ttm_in\t203.0.113.20:28001@1\t1')
gtm_preflight
gtm_nft_render | nft -f -
for address in 192.0.2.10 192.0.2.11; do
    nsenter -t "$client_ns" -n python3 tests/packet_probe.py client "$address" 28446
done
nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.11 28447 tcp
if nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28447 tcp 2>/dev/null; then
    printf 'An explicit bind forwarded another local address\n' >&2; exit 1
fi
# Removing balanced targets must not leave stale per-target chains behind.
GTM_RECORDS=($'F000006\tBalanced\tnftables\ttcp\t0.0.0.0\t28448\trandom\t1\tmasquerade\tany\t203.0.113.20:28001@1,203.0.113.21:28001@1\t1')
gtm_nft_render | nft -f -
ruleset=$(nft list table inet gre_manager)
if [[ $ruleset != *"chain b_F000006_tcp_1 "* ]]; then printf 'Balancing chain missing\n' >&2; exit 1; fi
GTM_RECORDS=($'F000006\tBalanced\tnftables\ttcp\t0.0.0.0\t28448\tsingle\t1\tmasquerade\tany\t203.0.113.20:28001@1\t1')
gtm_nft_render | nft -f -
ruleset=$(nft list table inet gre_manager)
if [[ $ruleset == *"chain b_F000006_"* ]]; then printf 'Stale balancing chain kept\n' >&2; exit 1; fi
if command -v iptables-restore >/dev/null; then
    GTM_RECORDS=($'F000007\tAll addresses\tiptables\ttcp\t0.0.0.0\t28449\tsingle\t1\tmasquerade\ttm_in\t203.0.113.20:28001@1\t1')
    gtm_preflight
    gtm_iptables_apply 4
    for address in 192.0.2.10 192.0.2.11; do
        nsenter -t "$client_ns" -n python3 tests/packet_probe.py client "$address" 28449 tcp
    done
    GTM_RECORDS=()
    gtm_iptables_apply 4
fi
GTM_RECORDS=()
gtm_nft_render | nft -f -
ip addr del 192.0.2.11/24 dev tm_in
printf 'PASS: all-address kernel forwards work on additional IPs; explicit binds stay scoped.\n'

# IPv6 additional addresses and dual-stack listeners on one port.
ip -6 addr add 2001:db8:1::10/64 dev tm_in nodad
ip -6 addr add 2001:db8:1::11/64 dev tm_in nodad
ip -6 addr add 2001:db8:2::1/64 dev tm_out nodad
nsenter -t "$client_ns" -n ip -6 addr add 2001:db8:1::2/64 dev tm_client nodad
nsenter -t "$client_ns" -n ip -6 route add default via 2001:db8:1::10
nsenter -t "$backend_ns" -n ip -6 addr add 2001:db8:2::20/64 dev tm_backend nodad
nsenter -t "$backend_ns" -n ip -6 route add default via 2001:db8:2::1
sysctl -qw net.ipv6.conf.all.forwarding=1
printf '%s\n' $'F000012\tAll IPv4\tnftables\tboth\t0.0.0.0\t28454\tsingle\t1\tmasquerade\tany\t203.0.113.20:28001@1\t1' \
    $'F000013\tAll IPv6\tnftables\tboth\t::\t28454\tsingle\t1\tmasquerade\tany\t[2001:db8:2::20]:28001@1\t1' > "$test_dir/dual.tsv"
gtm_load_records "$test_dir/dual.tsv"
gtm_preflight
gtm_nft_render | nft -f -
for address in 192.0.2.10 2001:db8:1::10 2001:db8:1::11; do
    nsenter -t "$client_ns" -n python3 tests/packet_probe.py client "$address" 28454
done
if command -v ip6tables-restore >/dev/null; then
    GTM_RECORDS=($'F000014\tAll IPv6\tiptables\ttcp\t::\t28455\tsingle\t1\tmasquerade\tany\t[2001:db8:2::20]:28001@1\t1')
    gtm_preflight
    gtm_iptables_apply 6
    for address in 2001:db8:1::10 2001:db8:1::11; do
        nsenter -t "$client_ns" -n python3 tests/packet_probe.py client "$address" 28455 tcp
    done
    GTM_RECORDS=()
    gtm_iptables_apply 6
fi
GTM_RECORDS=()
gtm_nft_render | nft -f -
sysctl -qw net.ipv6.conf.all.forwarding=0
printf 'PASS: IPv6 additional addresses forward; IPv4 and IPv6 share a port.\n'

# An additional IP with its own gateway (source policy routing). Upstream
# anti-spoofing is modelled by strict rp_filter in the client namespace: a reply
# from 198.51.100.10 is accepted only through that address's own link.
ip link add tm_in2 type veth peer name tm_client2
ip link set tm_client2 netns "$client_ns"
ip addr add 198.51.100.10/24 dev tm_in2
ip link set tm_in2 up
nsenter -t "$client_ns" -n ip link set lo up
nsenter -t "$client_ns" -n ip addr add 100.64.0.5/32 dev lo
nsenter -t "$client_ns" -n ip addr add 198.51.100.2/24 dev tm_client2
nsenter -t "$client_ns" -n ip link set tm_client2 up
nsenter -t "$client_ns" -n ip route add 198.51.100.10/32 dev tm_client2 src 100.64.0.5
for key in all tm_client tm_client2; do nsenter -t "$client_ns" -n sysctl -qw "net.ipv4.conf.$key.rp_filter=1"; done
for key in all tm_in tm_in2; do sysctl -qw "net.ipv4.conf.$key.rp_filter=2"; done
ip route add default via 192.0.2.2 dev tm_in
ip rule add pref 1000 from 198.51.100.10 lookup 100
ip route add default via 198.51.100.2 dev tm_in2 table 100
saved_state=$GTM_STATE GTM_STATE=$test_dir/policy.tsv
for engine in nftables iptables; do
    [[ $engine == nftables ]] || command -v iptables-restore >/dev/null || continue
    printf '%s\n' $'F000015\tAll addresses\t'"$engine"$'\ttcp\t0.0.0.0\t28456\tsingle\t1\tmasquerade\tany\t203.0.113.20:28001@1\t1' \
        $'F000016\tMain only\t'"$engine"$'\ttcp\t192.0.2.10\t28457\tsingle\t1\tmasquerade\tany\t203.0.113.20:28001@1\t1' > "$GTM_STATE"
    gtm_load_records
    gtm_preflight
    gtm_kernel_apply >/dev/null
    [[ $(ip rule show) == *"31001:"*"from all fwmark 0x1000000/0xf000000 lookup 100"* ]] || { printf 'Return rule missing (%s)\n' "$engine" >&2; exit 1; }
    nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 198.51.100.10 28456 tcp
    nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28456 tcp
    # Without the owned rule, replies leave through the main gateway and are dropped.
    ip rule del pref 31001 fwmark 0x1000000/0xf000000 lookup 100
    if nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 198.51.100.10 28456 tcp 2>/dev/null; then
        printf 'Policy-routed address worked without its return rule (%s)\n' "$engine" >&2; exit 1
    fi
    gtm_kernel_apply >/dev/null
    nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 198.51.100.10 28456 tcp
done
sysctl -qw net.ipv4.conf.tm_in2.rp_filter=1
report=$(gtm_doctor_addresses)
sysctl -qw net.ipv4.conf.tm_in2.rp_filter=2
for expected in '198.51.100.10 on tm_in2 / table 100 / return rule active' 'Strict rp_filter drops forwarded flows that enter on tm_in2' 'F000016 listens only on 192.0.2.10; 2 other local IPv4 address(es) are not forwarded.'; do
    [[ $report == *"$expected"* ]] || { printf 'Doctor report lacks: %s\n%s\n' "$expected" "$report" >&2; exit 1; }
done
: > "$GTM_STATE"
gtm_kernel_apply >/dev/null
[[ $(ip rule show) != *0xf000000* ]] || { printf 'Owned return rule survived without records\n' >&2; exit 1; }
[[ $(ip rule show) == *"from 198.51.100.10 lookup 100"* ]] || { printf 'Foreign policy rule was removed\n' >&2; exit 1; }
ip rule del pref 1000 from 198.51.100.10 lookup 100
ip route flush table 100
ip route del default via 192.0.2.2 dev tm_in
ip link del tm_in2
for key in all tm_client; do nsenter -t "$client_ns" -n sysctl -qw "net.ipv4.conf.$key.rp_filter=0"; done
GTM_STATE=$saved_state
printf 'PASS: replies for an additional IP with its own gateway follow its routing table.\n'

# Maintenance: reapplying rules keeps established flows; a flow reset clears
# only the selected forward's DNAT entries.
if command -v conntrack >/dev/null; then
    saved_state=$GTM_STATE GTM_STATE=$test_dir/flows.tsv
    printf '%s\n' $'F000017\tReset me\tnftables\ttcp\t0.0.0.0\t28458\tsingle\t1\tmasquerade\tany\t203.0.113.20:28001@1\t1' \
        $'F000018\tKeep me\tnftables\ttcp\t192.0.2.10\t28459\tsingle\t1\tmasquerade\tany\t203.0.113.20:28001@1\t1' > "$GTM_STATE"
    gtm_load_records
    gtm_preflight
    gtm_kernel_apply >/dev/null
    hold='import socket, sys, time
held = [socket.create_connection((sys.argv[1], int(sys.argv[2]))) for _ in range(int(sys.argv[3]))]
time.sleep(30)'
    nsenter -t "$client_ns" -n python3 -c "$hold" 192.0.2.10 28458 2 & hold_reset=$!
    nsenter -t "$client_ns" -n python3 -c "$hold" 192.0.2.10 28459 1 & hold_keep=$!
    flows() { conntrack -L -p tcp --orig-port-dst "$1" 2>/dev/null | grep -c ESTABLISHED || true; }
    for _ in $(seq 50); do [[ $(flows 28458) == 2 && $(flows 28459) == 1 ]] && break; sleep 0.1; done
    [[ $(flows 28458) == 2 && $(flows 28459) == 1 ]] || { printf 'Held flows missing: %s/%s\n' "$(flows 28458)" "$(flows 28459)" >&2; exit 1; }
    gtm_kernel_apply >/dev/null
    [[ $(flows 28458) == 2 && $(flows 28459) == 1 ]] || { printf 'Rule refresh dropped established flows\n' >&2; exit 1; }
    result=$(gtm_flows_reset F000017)
    [[ $result == 'Cleared 2 tracked flow(s) for F000017;'* ]] || { printf 'Unexpected reset result: %s\n' "$result" >&2; exit 1; }
    [[ $(flows 28458) == 0 && $(flows 28459) == 1 ]] || { printf 'Flow reset touched other forwards: %s/%s\n' "$(flows 28458)" "$(flows 28459)" >&2; exit 1; }
    kill "$hold_reset" "$hold_keep" 2>/dev/null || true
    wait "$hold_reset" "$hold_keep" 2>/dev/null || true
    : > "$GTM_STATE"
    gtm_kernel_apply >/dev/null
    GTM_STATE=$saved_state
    printf 'PASS: rule refresh keeps established flows; flow reset clears only the selected forward.\n'
else
    printf 'SKIP: conntrack CLI unavailable; flow reset fixture not run.\n'
fi

# Health failover: a runtime exclusion sends every new connection of a
# balanced forward to the live destination; clearing it restores the spread.
saved_state=$GTM_STATE GTM_STATE=$test_dir/failover.tsv
printf '%s\n' $'F000019\tPool\tnftables\ttcp\t192.0.2.10\t28460\troundrobin\t1\tmasquerade\tany\t203.0.113.20:28001@1,203.0.113.20:28009@1\t1' > "$GTM_STATE"
gtm_load_records
gtm_preflight
gtm_kernel_apply >/dev/null
failed=0
for _ in 1 2 3 4; do nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28460 tcp 2>/dev/null || ((failed+=1)); done
((failed == 2)) || { printf 'Round robin should reach the dead destination twice, failed %d\n' "$failed" >&2; exit 1; }
result=$(gtm_forward_exclude F000019 2)
[[ $result == *'Destinations 2 of F000019 receive no new flows'* ]] || { printf 'Unexpected exclusion result: %s\n' "$result" >&2; exit 1; }
for _ in 1 2 3 4; do nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28460 tcp; done
packets=$(nft -j list chain inet gre_manager b_F000019_tcp_0 | python3 -c 'import json,sys; print(sum(e["counter"]["packets"] for i in json.load(sys.stdin)["nftables"] if "rule" in i for e in i["rule"]["expr"] if "counter" in e))')
((packets >= 4)) || { printf 'Destination counter did not count new connections: %s\n' "$packets" >&2; exit 1; }
gtm_forward_exclude F000019 - >/dev/null
[[ ! -s $(gtm_exclusions_file) ]] || { printf 'Exclusion survived the restore\n' >&2; exit 1; }
failed=0
for _ in 1 2 3 4; do nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28460 tcp 2>/dev/null || ((failed+=1)); done
((failed == 2)) || { printf 'Restoring the destination did not restore the spread (%d failures)\n' "$failed" >&2; exit 1; }
: > "$GTM_STATE"
gtm_kernel_apply >/dev/null
GTM_STATE=$saved_state
printf 'PASS: failover keeps new connections off an excluded destination; per-destination counters count them.\n'

# Real GRE encapsulation using the retained key/address/MTU contracts.
ip tunnel add gre10 mode gre local 203.0.113.1 remote 203.0.113.20 key 10
nsenter -t "$backend_ns" -n ip tunnel add gre-out-10 mode gre local 203.0.113.20 remote 203.0.113.1 key 10
ip address add 10.0.10.1/30 dev gre10
nsenter -t "$backend_ns" -n ip address add 10.0.10.2/30 dev gre-out-10
ip link set gre10 mtu 1430 up
nsenter -t "$backend_ns" -n ip link set gre-out-10 mtu 1430 up
GTM_RECORDS=($'F000010\tGRE packet test\tnftables\tboth\t192.0.2.10\t28445\tsingle\t1\tmasquerade\ttm_in\t10.0.10.2:28001@1\t1')
gtm_preflight
gtm_nft_render | nft -f -
python3 tests/packet_probe.py mss gre10 10.0.10.2 1390 & capture_pid=$!
sleep 0.2
nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28445 tcp 131072
wait "$capture_pid"; capture_pid=''
# A peer advertising a smaller MSS must never have it increased by the rule.
python3 tests/packet_probe.py mss gre10 10.0.10.2 1200 & capture_pid=$!
sleep 0.2
nsenter -t "$client_ns" -n env GTM_TEST_TCP_MSS=1200 python3 tests/packet_probe.py client 192.0.2.10 28445 tcp 131072
wait "$capture_pid"; capture_pid=''
nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28445 udp 1200
GTM_RECORDS=()
gtm_nft_render | nft -f -
ip link del gre10
nsenter -t "$backend_ns" -n ip link del gre-out-10

if command -v iptables-restore >/dev/null; then
    GTM_RECORDS=($'F000001\tKernel forward\tiptables\tboth\t192.0.2.10\t443\trandom\t1\tmasquerade\tany\t203.0.113.20:443@3,203.0.113.21:8443@1\t1')
    gtm_iptables_apply 4
    gtm_iptables_apply 4
    [[ $(iptables -t nat -S PREROUTING | grep -c -- '-j GTM_PRE') == 1 ]]
    [[ $(iptables -t nat -S GTM_PRE | grep -c -- '-j DNAT') == 4 ]]
    GTM_RECORDS=()
    gtm_iptables_apply 4
    if iptables -t nat -S GTM_PRE | grep -q -- '-j DNAT'; then printf 'Owned iptables DNAT kept\n' >&2; exit 1; fi
    GTM_RECORDS=($'F000003\tPacket test\tiptables\tboth\t192.0.2.10\t28444\tsingle\t1\tmasquerade\ttm_in\t203.0.113.20:28001@1\t1')
    gtm_preflight
    gtm_iptables_apply 4
    iptables -P FORWARD DROP
    nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28444
    GTM_RECORDS=()
    gtm_iptables_apply 4
    iptables -P FORWARD ACCEPT
fi

if command -v haproxy >/dev/null; then
    line=$'F000001\tChecked failover\thaproxy\ttcp\t0.0.0.0\t28443\tfailover\t1\tpreserve\tany\t203.0.113.20:28002@1,203.0.113.20:28001@1\t2\tidle=86400;tunnel=86400;fin=30;retries=2'
    gtm_record_validate "$line"
    gtm_relay_loop_check
    gtm_haproxy_render > "$test_dir/haproxy.conf"
    haproxy -c -f "$test_dir/haproxy.conf"
    if command -v systemd-analyze >/dev/null; then
        gtm_haproxy_unit "$(command -v haproxy)" "$test_dir/haproxy.conf" F000001 > "$test_dir/gtm-F000001.service"
        systemd-analyze verify --man=no "$test_dir/gtm-F000001.service"
    fi
    haproxy -W -db -f "$test_dir/haproxy.conf" > "$test_dir/haproxy.log" 2>&1 & relay_pid=$!
    sleep 0.3
    python3 tests/packet_probe.py client 127.0.0.1 28443 tcp
    if command -v socat >/dev/null; then
        old_worker=$(gtm_haproxy_pid F000001)
        gtm_haproxy_status F000001
        python3 tests/haproxy_probe.py hold 28443 "$test_dir/held-ready" "$test_dir/held-proceed" & held_pid=$!
        for attempt in {1..40}; do [[ ! -f $test_dir/held-ready ]] || break; sleep 0.05; done
        [[ -f $test_dir/held-ready ]]
        H_IDLE=7200; gtm_haproxy_render > "$test_dir/haproxy.conf"
        haproxy -c -f "$test_dir/haproxy.conf"
        kill -USR2 "$relay_pid"
        (systemctl() { [[ $1 == is-active ]]; }; gtm_haproxy_wait F000001 "$old_worker")
        touch "$test_dir/held-proceed"
        wait "$held_pid"; held_pid=''
        python3 tests/packet_probe.py client 127.0.0.1 28443 tcp
    fi
    kill "$relay_pid"; wait "$relay_pid" || true; relay_pid=''
    # The data port is reachable, but the separate application probe is 503.
    # Changing its readiness must affect new connections without changing data bytes.
    nsenter -t "$backend_ns" -n python3 tests/http_health_probe.py "$test_dir/http-ready" > "$test_dir/http-health.log" 2>&1 & health_pid=$!
    line=$'F000001\tHTTP readiness\thaproxy\ttcp\t0.0.0.0\t28443\tsingle\t1\tpreserve\tany\t203.0.113.20:28001@1\t2\tcheck_mode=http;check_port=28004;check_path=/ready/live;check_host=health.example.com;check_status=204;check_interval=1;check_fall=1;check_rise=1;check_timeout=1'
    gtm_record_validate "$line"
    gtm_haproxy_render > "$test_dir/haproxy.conf"
    haproxy -c -f "$test_dir/haproxy.conf"
    haproxy -W -db -f "$test_dir/haproxy.conf" > "$test_dir/haproxy.log" 2>&1 & relay_pid=$!
    sleep 1.5
    if python3 tests/packet_probe.py client 127.0.0.1 28443 tcp > "$test_dir/http-unready.log" 2>&1; then
        printf 'HTTP readiness incorrectly accepted an unhealthy application.\n' >&2; exit 1
    fi
    touch "$test_dir/http-ready"
    for attempt in {1..30}; do
        if python3 tests/packet_probe.py client 127.0.0.1 28443 tcp > "$test_dir/http-ready.log" 2>&1; then break; fi
        sleep 0.1
    done
    python3 tests/packet_probe.py client 127.0.0.1 28443 tcp
    rm "$test_dir/http-ready"
    sleep 1.5
    if python3 tests/packet_probe.py client 127.0.0.1 28443 tcp > "$test_dir/http-unready.log" 2>&1; then exit 1; fi
    kill "$relay_pid" "$health_pid"; wait "$relay_pid" || true; wait "$health_pid" || true; relay_pid=''; health_pid=''
    printf 'PASS: HTTP readiness rejects reachable-but-unhealthy targets and recovers without changing TCP data.\n'
    # Real exact Host/path, SNI passthrough and TLS termination routing.
    mkdir -m 700 "$test_dir/certificates"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$test_dir/route.key" -out "$test_dir/route.crt" -subj /CN=route-b.test -addext subjectAltName=DNS:route-b.test,DNS:route-a.test -days 1 > "$test_dir/route-cert.log" 2>&1
    cat "$test_dir/route.crt" "$test_dir/route.key" > "$test_dir/certificates/test.pem"
    chmod 600 "$test_dir/certificates/test.pem"
    nsenter -t "$backend_ns" -n python3 tests/routing_probe.py serve "$test_dir/route.crt" "$test_dir/route.key" > "$test_dir/routing-server.log" 2>&1 & routing_pid=$!
    sleep 0.3
    for routing_mode in http sni https; do
        route_cert=-; route_path=/special; target_a=28005; target_b=28006; request_mode=http
        if [[ $routing_mode == sni ]]; then route_path=-; target_a=28007; target_b=28008; request_mode=https; fi
        if [[ $routing_mode == https ]]; then route_cert=test; request_mode=https; fi
        line=$'F000001\tApplication routing\thaproxy\ttcp\t0.0.0.0\t28443\troundrobin\t1\tpreserve\tany\t'
        line+="203.0.113.20:$target_a@1,203.0.113.20:$target_b@1"$'\t4\tconnect=5\t'"1|$routing_mode|$route_cert|route-b.test~$route_path~2"
        gtm_record_validate "$line"
        if [[ $routing_mode == https ]]; then (GTM_CONFIG_DIR=$test_dir; gtm_haproxy_certificate >/dev/null); fi
        (GTM_CONFIG_DIR=$test_dir; gtm_haproxy_render) > "$test_dir/haproxy.conf"
        haproxy -c -f "$test_dir/haproxy.conf"
        haproxy -W -db -f "$test_dir/haproxy.conf" > "$test_dir/haproxy.log" 2>&1 & relay_pid=$!
        sleep 0.3
        python3 tests/routing_probe.py client "$request_mode" 28443 route-b.test /special/child B "$test_dir/route.crt"
        kill "$relay_pid"; wait "$relay_pid" || true; relay_pid=''
    done
    # Source-IP memory affinity must keep repeated IPv4 connections on one target.
    line=$'F000001\tRemember clients\thaproxy\ttcp\t0.0.0.0\t28443\troundrobin\t1\tpreserve\tany\t203.0.113.20:28005@1,203.0.113.20:28006@1\t2\tstick=source;stick_size=1024;stick_expire=60'
    gtm_record_validate "$line"; gtm_haproxy_render > "$test_dir/haproxy.conf"
    haproxy -c -f "$test_dir/haproxy.conf"
    haproxy -W -db -f "$test_dir/haproxy.conf" > "$test_dir/haproxy.log" 2>&1 & relay_pid=$!
    sleep 0.3
    affinity_target=$(python3 tests/routing_probe.py client http 28443 route-a.test / 'A|B' "$test_dir/route.crt")
    for attempt in {1..5}; do python3 tests/routing_probe.py client http 28443 route-a.test / "$affinity_target" "$test_dir/route.crt"; done
    kill "$relay_pid"; wait "$relay_pid" || true; relay_pid=''
    printf 'PASS: bounded source-IP affinity preserves the selected target across new connections.\n'
    line=${line/$'\t0.0.0.0\t'/$'\t::\t'}
    gtm_record_validate "$line"; gtm_haproxy_render > "$test_dir/haproxy.conf"
    haproxy -c -f "$test_dir/haproxy.conf"
    haproxy -W -db -f "$test_dir/haproxy.conf" > "$test_dir/haproxy.log" 2>&1 & relay_pid=$!
    sleep 0.3
    affinity_target=$(python3 tests/routing_probe.py client http 28443 route-a.test / 'A|B' "$test_dir/route.crt" ::1)
    for attempt in {1..3}; do python3 tests/routing_probe.py client http 28443 route-a.test / "$affinity_target" "$test_dir/route.crt" ::1; done
    kill "$relay_pid"; wait "$relay_pid" || true; relay_pid=''
    printf 'PASS: bounded source-IP affinity supports IPv6 clients.\n'

    kill "$routing_pid"; wait "$routing_pid" || true; routing_pid=''
    printf 'PASS: exact Host/path routing, SNI passthrough and verified HTTPS termination.\n'
    nsenter -t "$backend_ns" -n python3 tests/haproxy_probe.py server 192.0.2.2 > "$test_dir/proxy-server.log" 2>&1 & proxy_server_pid=$!
    sleep 0.2
    for proxy_version in v1 v2; do
        line=$'F000001\tPROXY metadata\thaproxy\ttcp\t192.0.2.10\t28443\tsingle\t1\tpreserve\tany\t203.0.113.20:28003@1\t2\tproxy='
        line+="$proxy_version;check_interval=1;slowstart=2;server_maxconn=20;idle=86400;log=errors"
        gtm_record_validate "$line"
        gtm_haproxy_render > "$test_dir/haproxy.conf"
        haproxy -c -f "$test_dir/haproxy.conf"
        haproxy -W -db -f "$test_dir/haproxy.conf" > "$test_dir/haproxy.log" 2>&1 & relay_pid=$!
        sleep 0.3
        nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28443 tcp
        kill "$relay_pid"; wait "$relay_pid" || true; relay_pid=''
    done
    kill "$proxy_server_pid"; wait "$proxy_server_pid" || true; proxy_server_pid=''
fi

if command -v realm >/dev/null; then
    line=$'F000001\tRealm test\trealm\tboth\t0.0.0.0\t28443\tsingle\t1\tpreserve\tany\t203.0.113.20:28001@1\t1'
    gtm_record_validate "$line"
    gtm_relay_loop_check
    gtm_realm_render > "$test_dir/realm.toml"
    realm -c "$test_dir/realm.toml" > "$test_dir/realm.log" 2>&1 & relay_pid=$!
    sleep 0.3
    python3 tests/packet_probe.py client 127.0.0.1 28443
    nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28443
    kill "$relay_pid"; wait "$relay_pid" || true; relay_pid=''
    line=$'F000001\tRealm advanced\trealm\tboth\t0.0.0.0\t28443\tsingle\t1\tpreserve\tany\t203.0.113.20:28001@1\t3\ttcp_timeout=8;udp_timeout=45;tcp_keepalive=20;tcp_keepalive_probe=4;accept_proxy_timeout=2;log=error'
    gtm_record_validate "$line"
    gtm_realm_render > "$test_dir/realm.toml"
    realm -c "$test_dir/realm.toml" > "$test_dir/realm.log" 2>&1 & relay_pid=$!
    sleep 0.3
    python3 tests/packet_probe.py client 127.0.0.1 28443
    kill "$relay_pid"; wait "$relay_pid" || true; relay_pid=''
    nsenter -t "$backend_ns" -n python3 tests/haproxy_probe.py server 192.0.2.2 > "$test_dir/proxy-server.log" 2>&1 & proxy_server_pid=$!
    sleep 0.2
    for proxy_version in 1 2; do
        line=$'F000001\tRealm PROXY\trealm\ttcp\t192.0.2.10\t28443\tsingle\t1\tpreserve\tany\t203.0.113.20:28003@1\t3\tsend_proxy=true;send_proxy_version='
        line+="$proxy_version;log=error"
        gtm_record_validate "$line"; gtm_realm_render > "$test_dir/realm.toml"
        realm -c "$test_dir/realm.toml" > "$test_dir/realm.log" 2>&1 & relay_pid=$!
        sleep 0.3
        nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28443 tcp
        kill "$relay_pid"; wait "$relay_pid" || true; relay_pid=''
    done
    kill "$proxy_server_pid"; wait "$proxy_server_pid" || true; proxy_server_pid=''
    # A pair of pinned Realm WS profiles must carry unmodified TCP bytes.
    line=$'F000001\tRealm WS peer\trealm\ttcp\t203.0.113.20\t28009\tsingle\t1\tpreserve\tany\t127.0.0.1:28001@1\t3\tlisten_transport=ws;ws_host=relay.test;ws_path=/relay;log=error'
    gtm_record_validate "$line"; gtm_realm_profile_preflight; gtm_realm_render > "$test_dir/realm-peer.toml"
    nsenter -t "$backend_ns" -n realm -c "$test_dir/realm-peer.toml" > "$test_dir/realm-peer.log" 2>&1 & realm_peer_pid=$!
    line=$'F000001\tRealm WS entrance\trealm\ttcp\t0.0.0.0\t28443\tsingle\t1\tpreserve\tany\t203.0.113.20:28009@1\t3\tremote_transport=ws;ws_host=relay.test;ws_path=/relay;log=error'
    gtm_record_validate "$line"; gtm_realm_profile_preflight; gtm_realm_render > "$test_dir/realm.toml"
    realm -c "$test_dir/realm.toml" > "$test_dir/realm.log" 2>&1 & relay_pid=$!
    sleep 0.5
    python3 tests/packet_probe.py client 127.0.0.1 28443 tcp 131072
    kill "$relay_pid" "$realm_peer_pid"; wait "$relay_pid" "$realm_peer_pid" || true; relay_pid=''; realm_peer_pid=''
    printf 'PASS: pinned Realm WebSocket profiles carry TCP payloads.\n'
    printf 'PASS: Realm v3 network options and PROXY v1/v2 metadata on real traffic.\n'
fi

if command -v frpc >/dev/null && command -v frps >/dev/null; then
    P_NAME=namespace-test; P_HOST=127.0.0.1; P_CONTROL=27000; P_PUBLIC=28443
    P_LOCAL_IP=127.0.0.1; P_LOCAL_PORT=28001; P_PROTO=tcp; P_MUX=true
    P_TOKEN=abcdefghijklmnopqrstuvwx; P_GROUP=destinations
    P_INTERNAL=27001; P_GATEWAY_CERT="$test_dir/tls.pem"; P_TLS_CA="$test_dir/tls.crt"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$test_dir/tls.key" -out "$P_TLS_CA" -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 -days 1 > "$test_dir/cert.log" 2>&1
    cat "$P_TLS_CA" "$test_dir/tls.key" > "$P_GATEWAY_CERT"
    for P_TRANSPORT in tcp websocket wss quic kcp; do
        for P_ROLE in entrance destination; do
            gtm_frp_render > "$test_dir/frp.toml"
            if [[ $P_ROLE == entrance ]]; then frps verify -c "$test_dir/frp.toml"; else frpc verify -c "$test_dir/frp.toml"; fi
        done
        P_ROLE=entrance; gtm_frp_render > "$test_dir/frps.toml"
        P_ROLE=destination; P_LOCAL_IP=203.0.113.20; P_LOCAL_PORT=28001
        gtm_frp_render > "$test_dir/frpc.toml"
        frps -c "$test_dir/frps.toml" > "$test_dir/frps.log" 2>&1 & frps_pid=$!
        if [[ $P_TRANSPORT == wss ]]; then
            gtm_wss_haproxy_render > "$test_dir/gateway.conf"
            haproxy -c -f "$test_dir/gateway.conf"
            haproxy -db -f "$test_dir/gateway.conf" > "$test_dir/gateway.log" 2>&1 & gateway_pid=$!
        fi
        sleep 0.2
        frpc -c "$test_dir/frpc.toml" > "$test_dir/frpc.log" 2>&1 & frpc_pid=$!
        # Registration is asynchronous; KCP/TLS can need more than a fixed 0.7s.
        ready=0
        for ((attempt=0;attempt<50;attempt++)); do
            if [[ -n $(ss -Hltn "sport = :$P_PUBLIC") ]]; then ready=1; break; fi
            kill -0 "$frpc_pid" "$frps_pid" || break
            sleep 0.1
        done
        ((ready==1)) || { printf 'FRP %s did not expose its public TCP port.\n' "$P_TRANSPORT" >&2; exit 1; }
        python3 tests/packet_probe.py client 127.0.0.1 28443 tcp
        kill "$frpc_pid" "$frps_pid"; wait "$frpc_pid" "$frps_pid" || true
        frpc_pid=''; frps_pid=''
        if [[ -n ${gateway_pid:-} ]]; then kill "$gateway_pid"; wait "$gateway_pid" || true; gateway_pid=''; fi
    done
fi

if command -v rathole >/dev/null; then
    gtm_rathole_binary
    keys=$(rathole --genkey)
    private_key=$(awk '/^Private Key:/ {getline; print; exit}' <<< "$keys")
    public_key=$(awk '/^Public Key:/ {getline; print; exit}' <<< "$keys")
    RATH_NAME=namespace-test; RATH_HOST=127.0.0.1; RATH_CONTROL=27333; RATH_PUBLIC=28555
    RATH_LOCAL_IP=203.0.113.20; RATH_LOCAL_PORT=28001; RATH_PROTO=both
    RATH_TOKEN=abcdefghijklmnopqrstuvwx
    RATH_ROLE=entrance; RATH_KEY=$private_key; gtm_rathole_render > "$test_dir/rathole-server.toml"
    RATH_ROLE=destination; RATH_KEY=$public_key; gtm_rathole_render > "$test_dir/rathole-client.toml"
    RUST_LOG=warn rathole "$test_dir/rathole-server.toml" > "$test_dir/rathole-server.log" 2>&1 & rathole_server_pid=$!
    sleep 0.2
    # A different, otherwise valid server key must not establish a tunnel.
    RATH_KEY=$(rathole --genkey | awk '/^Public Key:/ {getline; print; exit}')
    gtm_rathole_render > "$test_dir/rathole-wrong-key.toml"
    RUST_LOG=warn rathole "$test_dir/rathole-wrong-key.toml" > "$test_dir/rathole-client.log" 2>&1 & rathole_client_pid=$!
    sleep 0.5
    if python3 tests/packet_probe.py client 127.0.0.1 28555 tcp 2> "$test_dir/expected-rejection.log"; then
        printf 'An incorrect Noise key established a tunnel\n' >&2; exit 1
    fi
    kill "$rathole_client_pid"; wait "$rathole_client_pid" || true; rathole_client_pid=''
    RUST_LOG=warn rathole "$test_dir/rathole-client.toml" > "$test_dir/rathole-client.log" 2>&1 & rathole_client_pid=$!
    sleep 0.7
    python3 tests/packet_probe.py client 127.0.0.1 28555 tcp 131072
    python3 tests/packet_probe.py client 127.0.0.1 28555 udp 1200
    kill "$rathole_client_pid" "$rathole_server_pid"; wait "$rathole_client_pid" "$rathole_server_pid" || true
    rathole_client_pid=''; rathole_server_pid=''
fi

if command -v iptables >/dev/null; then
    (
        GTM_CONFIG_DIR="$test_dir/manager"; GTM_SERVICE_DIR=$GTM_CONFIG_DIR
        GTM_SIMPLE_SCRIPT="$GTM_CONFIG_DIR/simple.sh"; gtm_paths
        mkdir -p "$GTM_CONFIG_DIR/backups"
        systemctl() { return 0; }; gtm_confirm() { return 0; }
        FW_SCRIPT="$GTM_CONFIG_DIR/legacy.sh"; FW_SERVICE="$GTM_CONFIG_DIR/legacy.service"
        printf '#!/bin/bash\n# Custom GRE Forwarding Rules\n' > "$FW_SCRIPT"
        for proto in tcp udp; do
            for repeat in 1 2; do
                iptables -t nat -A PREROUTING -p "$proto" --dport 28556 -j DNAT --to-destination 203.0.113.20:28001
            done
            iptables -t nat -A POSTROUTING -d 203.0.113.20 -p "$proto" --dport 28001 -j MASQUERADE
            iptables -I FORWARD -d 203.0.113.20 -p "$proto" --dport 28001 -j ACCEPT
            printf 'iptables -t nat -A PREROUTING -p %s --dport 28556 -j DNAT --to-destination 203.0.113.20:28001\n' "$proto" >> "$FW_SCRIPT"
            printf 'iptables -t nat -A POSTROUTING -d 203.0.113.20 -p %s --dport 28001 -j MASQUERADE\n' "$proto" >> "$FW_SCRIPT"
            printf 'iptables -I FORWARD -d 203.0.113.20 -p %s --dport 28001 -j ACCEPT\n' "$proto" >> "$FW_SCRIPT"
        done
        gtm_legacy_forward_unit > "$FW_SERVICE"
        iptables -N TEST_MANUAL
        iptables -A TEST_MANUAL -j RETURN
        nsenter -t "$client_ns" -n python3 tests/packet_probe.py client 192.0.2.10 28556
        gtm_legacy_cleanup_all
        if iptables -t nat -S PREROUTING | grep -q -- '--dport 28556'; then printf 'Unexpected success: %s\n' 'iptables -t nat -S PREROUTING  grep -q -- --dport 28556' >&2; exit 1; fi
        iptables -C TEST_MANUAL -j RETURN
        [[ ! -e $FW_SCRIPT && ! -e $FW_SERVICE ]]
        ip tunnel add gre_simp mode gre local 203.0.113.1 remote 203.0.113.20 ttl 255
        ip addr add 172.16.200.2/30 dev gre_simp
        ip link set gre_simp up
        cat > "$GTM_SIMPLE_SCRIPT" <<EOF
#!/bin/bash
# Generated by GRE Master - Simple Mode v12
ip tunnel add gre_simp mode gre local 203.0.113.1 remote 203.0.113.20 ttl 255
ip addr add 172.16.200.2/30 dev gre_simp
ip link set gre_simp up
EOF
        gtm_simple_unit > "$GTM_SIMPLE_UNIT"
        gtm_simple_cleanup
        if ip link show dev gre_simp >/dev/null 2>&1; then printf 'Unexpected success: %s\n' 'ip link show dev gre_simp /dev/null 21' >&2; exit 1; fi
        [[ ! -e $GTM_SIMPLE_SCRIPT && ! -e $GTM_SIMPLE_UNIT ]]
        iptables -C TEST_MANUAL -j RETURN
        printf 'PASS: real legacy duplicate cleanup and Simple GRE removal preserve unrelated rules.\n'
    )
fi
# Exercise paired FRP native validation, startup and guarded removal. Both
# processes live in private namespaces; the unit runner never contacts systemd.
if command -v frps >/dev/null && command -v frpc >/dev/null; then
    (
        GTM_CONFIG_DIR="$test_dir/pair-frp"; GTM_SERVICE_DIR=$GTM_CONFIG_DIR; mkdir -p "$GTM_CONFIG_DIR"
        gtm_paths
        trap 'for file in "$GTM_CONFIG_DIR"/*.pid; do [[ ! -f $file ]] || { read -r child < "$file"; kill "$child" 2>/dev/null || true; }; done' EXIT
        systemctl() {
            local verb=$1 unit=${*: -1} line child
            local -a args=()
            case $verb in
                daemon-reload) return 0;;
                enable)
                    while IFS= read -r line; do
                        [[ $line == ExecStart=* ]] || continue
                        read -r -a args <<< "${line#ExecStart=}"
                        [[ ${args[0]} == "$(command -v frps)" || ${args[0]} == "$(command -v frpc)" ]] || return 1
                        if [[ $unit == gtm-frp-destination-* ]]; then
                            nsenter -t "$backend_ns" -n "${args[@]}" > "$GTM_CONFIG_DIR/$unit.log" 2>&1 &
                        else "${args[@]}" > "$GTM_CONFIG_DIR/$unit.log" 2>&1 & fi
                        printf '%s\n' "$!" > "$GTM_CONFIG_DIR/$unit.pid"
                    done < "$GTM_SERVICE_DIR/$unit.service";;
                is-active) read -r child < "$GTM_CONFIG_DIR/$unit.pid"; kill -0 "$child";;
                disable) read -r child < "$GTM_CONFIG_DIR/$unit.pid"; kill "$child" && rm -f "$GTM_CONFIG_DIR/$unit.pid";;
                *) return 1;;
            esac
        }
        entrance=$'frp\tpair-namespace\tentrance\t203.0.113.1\t28660\t28661\t127.0.0.1\t28001\ttcp\ttcp\ttrue\tabcdefghijklmnopqrstuvwxyz123456\tpair-namespace\t-\t-\t0'
        destination=${entrance/$'\tentrance\t'/$'\tdestination\t'}
        revision=$(gtm_pair_api pair-check-frp <<< "$entrance")
        peer_revision=$(gtm_pair_api pair-check-frp <<< "$destination")
        fingerprint=$(gtm_pair_api pair-apply-frp "$revision" <<< "$entrance")
        peer_fingerprint=$(gtm_pair_api pair-apply-frp "$peer_revision" <<< "$destination")
        python3 tests/packet_probe.py client 203.0.113.1 28661 tcp
        gtm_pair_api pair-delete gtm-frp-destination-pair-namespace "$peer_fingerprint"
        gtm_pair_api pair-delete gtm-frp-entrance-pair-namespace "$fingerprint"
        printf 'PASS: paired FRP validates, carries TCP, and removes only its fingerprint-matching resources.\n'
    )
fi
# Exercise the paired GRE compare/apply/delete boundary with real interfaces in
# two existing private namespaces. Only systemd is replaced by a unit runner.
(
    GTM_CONFIG_DIR="$test_dir/pair-a"; GTM_SERVICE_DIR=$GTM_CONFIG_DIR; mkdir -p "$GTM_CONFIG_DIR"
    gtm_paths
    systemctl() {
        local verb=$1 unit=${*: -1} line
        local -a args=()
        case $verb in
            daemon-reload) return 0;;
            enable)
                while IFS= read -r line; do
                    [[ $line == ExecStart=* ]] || continue
                    read -r -a args <<< "${line#ExecStart=}"
                    [[ ${args[0]} == /sbin/ip ]] || return 1
                    ip "${args[@]:1}" || return 1
                done < "$GTM_SERVICE_DIR/$unit.service";;
            disable) ip link del dev gre-out-240;;
            *) return 1;;
        esac
    }
    revision=$(gtm_pair_api pair-check-gre 240 iran 203.0.113.20 203.0.113.1 1430)
    fingerprint=$(gtm_pair_api pair-apply-gre "$revision" 240 iran 203.0.113.20 203.0.113.1 1430)
    nsenter -t "$backend_ns" -n bash -c '
        source ./gre.sh; gtm_paths
        GTM_CONFIG_DIR=$1; GTM_SERVICE_DIR=$1; GTM_RUN_DIR=$1; mkdir -p "$1"
        systemctl() { return 0; }
        gtm_link_create 240 kharej 203.0.113.1 203.0.113.20 1430
    ' _ "$test_dir/pair-b" >/dev/null
    # The destination unit above is rendered but this isolated namespace has no
    # systemd. Execute only its validated ip ExecStart arrays in that namespace.
    while IFS= read -r line; do
        [[ $line == ExecStart=* ]] || continue
        read -r -a args <<< "${line#ExecStart=}"
        [[ ${args[0]} == /sbin/ip ]]
        nsenter -t "$backend_ns" -n ip "${args[@]:1}"
    done < "$test_dir/pair-b/gre-tun-240.service"
    python3 tests/packet_probe.py client 10.0.240.1 28001
    gtm_pair_api pair-verify gre-tun-240 "$fingerprint"
    printf '# edited by operator\n' >> "$GTM_SERVICE_DIR/gre-tun-240.service"
    if gtm_pair_api pair-delete gre-tun-240 "$fingerprint"; then printf 'Unexpected success: %s\n' 'gtm_pair_api pair-delete gre-tun-240 fingerprint' >&2; exit 1; fi
    ip link show gre-out-240 >/dev/null
    sed -i '$d' "$GTM_SERVICE_DIR/gre-tun-240.service"
    gtm_pair_api pair-delete gre-tun-240 "$fingerprint"
    if ip link show gre-out-240 >/dev/null 2>&1; then printf 'Unexpected success: %s\n' 'ip link show gre-out-240 /dev/null 21' >&2; exit 1; fi
    nsenter -t "$backend_ns" -n ip link del dev gre240
    printf 'PASS: paired GRE carries TCP/UDP and fingerprint recovery preserves operator changes.\n'
)
printf 'PASS: isolated nftables IPv4/IPv6, idempotence, deletion and available engine checks.\n'
