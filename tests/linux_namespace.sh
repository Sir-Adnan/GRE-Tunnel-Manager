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
    for child in "${held_pid:-}" "${proxy_server_pid:-}" "${capture_pid:-}" "${rathole_client_pid:-}" "${rathole_server_pid:-}" "${gateway_pid:-}" "${relay_pid:-}" "${frpc_pid:-}" "${frps_pid:-}" "${server_pid:-}" "${client_ns:-}" "${backend_ns:-}"; do [[ -z $child ]] || kill "$child" 2>/dev/null || true; done
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
GTM_RECORDS=()
gtm_nft_render > "$test_dir/rules.nft"
nft -f "$test_dir/rules.nft"
! nft list table inet gre_manager | grep -q 'gtm-F000001'

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
    ! iptables -t nat -S GTM_PRE | grep -q -- '-j DNAT'
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
    line=$'F000001\tChecked failover\thaproxy\ttcp\t0.0.0.0\t28443\tfailover\t1\tpreserve\tany\t203.0.113.20:28002@1,203.0.113.20:28001@1\t1'
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
fi

if command -v frpc >/dev/null && command -v frps >/dev/null; then
    P_NAME=namespace-test; P_HOST=127.0.0.1; P_CONTROL=27000; P_PUBLIC=28443
    P_LOCAL_IP=127.0.0.1; P_LOCAL_PORT=28001; P_PROTO=tcp; P_MUX=true
    P_TOKEN=abcdefghijklmnopqrstuvwx; P_GROUP=destinations
    P_INTERNAL=27001; P_GATEWAY_CERT="$test_dir/tls.pem"; P_TLS_CA="$test_dir/tls.crt"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$test_dir/tls.key" -out "$P_TLS_CA" -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 -days 1 > "$test_dir/cert.log" 2>&1
    cat "$P_TLS_CA" "$test_dir/tls.key" > "$P_GATEWAY_CERT"
    for P_TRANSPORT in tcp websocket wss quic; do
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
        sleep 0.7
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
        ! iptables -t nat -S PREROUTING | grep -q -- '--dport 28556'
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
        ! ip link show dev gre_simp >/dev/null 2>&1
        [[ ! -e $GTM_SIMPLE_SCRIPT && ! -e $GTM_SIMPLE_UNIT ]]
        iptables -C TEST_MANUAL -j RETURN
        printf 'PASS: real legacy duplicate cleanup and Simple GRE removal preserve unrelated rules.\n'
    )
fi
printf 'PASS: isolated nftables IPv4/IPv6, idempotence, deletion and available engine checks.\n'
