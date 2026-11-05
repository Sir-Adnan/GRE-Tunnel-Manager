# Guided "why is this connection down" check for one connection or GRE
# tunnel. Read-only: it reads state, units, interfaces, rules and sysctls,
# and lists the endpoints the panel then probes. Output lines:
#   check<TAB>KEY<TAB>ok|warn|fail|info<TAB>DETAIL
#   probe<TAB>tcp|udp|icmp<TAB>ADDRESS<TAB>PORT<TAB>KEY
# KEY names the check; the panel translates it and suggests a fix.

gtm_diag() { printf 'check\t%s\t%s\t%s\n' "$1" "$2" "${3:-}"; }

gtm_diag_sysctl() { sysctl -n "$1" 2>/dev/null || cat "/proc/sys/${1//.//}" 2>/dev/null; }

# Conntrack table pressure is the most common cause of a forwarder that
# accepts some flows and silently drops new ones.
gtm_diag_conntrack() {
    local used maximum percent
    used=$(gtm_diag_sysctl net.netfilter.nf_conntrack_count) && maximum=$(gtm_diag_sysctl net.netfilter.nf_conntrack_max) || return 0
    [[ $used =~ ^[0-9]+$ && $maximum =~ ^[1-9][0-9]*$ ]] || return 0
    percent=$((10#$used * 100 / 10#$maximum))
    if ((percent >= 90)); then gtm_diag conntrack fail "$used/$maximum"
    elif ((percent >= 75)); then gtm_diag conntrack warn "$used/$maximum"
    else gtm_diag conntrack ok "$used/$maximum"; fi
}

gtm_diag_service() {
    local unit=$1 state
    command -v systemctl >/dev/null 2>&1 || { gtm_diag service info 'systemctl unavailable'; return; }
    state=$(systemctl is-active "$unit" 2>/dev/null) || :
    case $state in
        active) gtm_diag service ok "$unit";;
        activating|reloading) gtm_diag service warn "$unit $state";;
        *) gtm_diag service fail "$unit ${state:-inactive}";;
    esac
}

gtm_diag_forward_rules() {
    local id=$1 family=$2 count=0
    case $R_ENGINE in
        nftables)
            command -v nft >/dev/null 2>&1 || { gtm_diag component fail nft; return; }
            count=$(nft list table inet gre_manager 2>/dev/null | grep -c -- "\"gtm-$id\"") || :;;
        iptables)
            local tool=iptables-save
            [[ $family == 4 ]] || tool=ip6tables-save
            command -v "$tool" >/dev/null 2>&1 || { gtm_diag component fail "$tool"; return; }
            count=$("$tool" -t nat 2>/dev/null | grep -c -- "gtm-$id ") || :;;
    esac
    if ((count > 0)); then gtm_diag rules ok "$count"; else gtm_diag rules fail "$R_ENGINE"; fi
}

gtm_diag_listener() {
    local port=$1 proto=$2 flags=-Hltn
    command -v ss >/dev/null 2>&1 || return 0
    [[ $proto != udp ]] || flags=-Hlun
    if ss "$flags" "sport = :$((10#$port))" 2>/dev/null | grep -q .; then gtm_diag listener ok "$proto/$port"
    else gtm_diag listener fail "$proto/$port"; fi
}

gtm_diag_route() {
    local address=$1 route dev
    command -v ip >/dev/null 2>&1 || return 0
    route=$(ip -o route get "$address" 2>/dev/null) || { gtm_diag route fail "$address"; return; }
    [[ $route =~ \ dev\ ([^ ]+) ]] && dev=${BASH_REMATCH[1]} || dev=-
    if [[ $dev != - && -r /sys/class/net/$dev/operstate && $(cat "/sys/class/net/$dev/operstate") == down ]]; then gtm_diag route fail "$address via $dev (down)"
    else gtm_diag route ok "$address via $dev"; fi
}

gtm_diagnose_connection() {
    local id=$1 line found=0 family=4 forwarding target address port proto excluded
    local -a targets=()
    gtm_load_records || return 1
    for line in ${GTM_RECORDS[@]+"${GTM_RECORDS[@]}"}; do
        gtm_record_validate "$line" || return 1
        [[ $R_ID == "$id" ]] && { found=1; break; }
    done
    ((found)) || { gtm_error 'Connection not found.'; return 1; }
    [[ $R_BIND != *:* ]] || family=6
    if [[ $R_ENABLED == 1 ]]; then gtm_diag enabled ok; else gtm_diag enabled fail; fi
    case $R_ENGINE in
        iptables|nftables)
            if [[ $family == 4 ]]; then forwarding=$(gtm_diag_sysctl net.ipv4.ip_forward); else forwarding=$(gtm_diag_sysctl net.ipv6.conf.all.forwarding); fi
            if [[ $forwarding == 1 ]]; then gtm_diag forwarding ok "IPv$family"; else gtm_diag forwarding fail "IPv$family=${forwarding:-?}"; fi
            [[ $R_ENABLED != 1 ]] || gtm_diag_forward_rules "$id" "$family"
            excluded=$(awk -F '\t' -v id="$id" '$1 == id {print $3}' "$(gtm_exclusions_file)" 2>/dev/null)
            if [[ -n $excluded && $excluded != - ]]; then gtm_diag failover warn "$excluded"; fi;;
        *)
            gtm_diag_service "gtm-$id"
            for proto in tcp udp; do
                [[ $R_PROTO == "$proto" || $R_PROTO == both ]] && gtm_diag_listener "$R_PORT" "$proto"
            done;;
    esac
    gtm_diag_conntrack
    if [[ $R_TARGETS =~ (^|,)[a-z0-9.-]*[a-z][a-z0-9.-]*: ]]; then
        if gtm_resolve_targets; then gtm_diag dns ok "$R_TARGETS"; else gtm_diag dns fail; fi
    fi
    IFS=, read -r -a targets <<< "$R_TARGETS"
    for target in "${targets[@]:0:8}"; do
        gtm_target "$target" || continue
        address=$EP_IP port=$EP_PORT
        gtm_diag_route "$address"
        proto=tcp; [[ $R_PROTO != udp ]] || proto=udp
        printf 'probe\t%s\t%s\t%s\tdestination\n' "$proto" "$address" "$port"
    done
}

gtm_diagnose_gre() {
    local tid=$1 unit iface remote source inner peer suffix state address strict policy
    tid=$((10#$tid)); unit="$GTM_SERVICE_DIR/gre-tun-$tid.service"
    [[ -f $unit && ! -L $unit ]] || { gtm_error 'GRE tunnel not found.'; return 1; }
    iface=$(awk '$1 ~ /ExecStart=\/sbin\/ip/ && /tunnel add/ {for (i=1;i<=NF;i++) if ($i == "add") {print $(i+1); exit}}' "$unit")
    remote=$(awk '/tunnel add/ {for (i=1;i<=NF;i++) if ($i == "remote") {print $(i+1); exit}}' "$unit")
    source=$(awk '/tunnel add/ {for (i=1;i<=NF;i++) if ($i == "local") {print $(i+1); exit}}' "$unit")
    [[ $iface =~ ^gre(-out-)?[0-9]{1,3}$ ]] && gtm_ip "$remote" && gtm_ip "$source" || { gtm_error 'Unrecognized GRE unit.'; return 1; }
    suffix=1; peer=2
    [[ $iface != gre-out-* ]] || { suffix=2; peer=1; }
    inner="10.0.$tid.$peer"
    gtm_diag_service "gre-tun-$tid"
    if [[ -d /sys/class/net/$iface ]]; then
        state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null)
        # GRE links report "unknown" while up: they have no carrier.
        if [[ $state == down ]]; then gtm_diag interface fail "$iface down"; else gtm_diag interface ok "$iface"; fi
    else
        gtm_diag interface fail "$iface missing"
    fi
    if command -v ip >/dev/null 2>&1; then
        if ip -o address show 2>/dev/null | awk '{print $4}' | grep -qx -- "$source/[0-9]*"; then gtm_diag local-address ok "$source"
        else gtm_diag local-address fail "$source"; fi
        address=$(ip -o -4 address show dev "$iface" 2>/dev/null | awk '{print $4; exit}')
        if [[ $address == "10.0.$tid.$suffix/30" ]]; then gtm_diag inner-address ok "$address"; else gtm_diag inner-address fail "${address:-none}"; fi
    fi
    strict=0
    for state in all "$iface"; do [[ $(cat "/proc/sys/net/ipv4/conf/$state/rp_filter" 2>/dev/null) != 1 ]] || strict=1; done
    if ((strict)); then gtm_diag rp-filter warn strict; else gtm_diag rp-filter ok; fi
    # A DROP input policy without a GRE accept rule blocks protocol 47 here;
    # the far side's firewall is checked by the probe from that side only.
    if command -v iptables >/dev/null 2>&1 && [[ $remote != *:* ]]; then
        policy=$(iptables -S INPUT 2>/dev/null | awk '$1 == "-P" {print $3; exit}')
        if [[ $policy == DROP ]] && ! iptables -S INPUT 2>/dev/null | grep -Eq -- '-p (gre|47) .*-j ACCEPT|-s '"$remote"'(/32)? .*-j ACCEPT'; then gtm_diag gre-input warn 'INPUT policy DROP'
        else gtm_diag gre-input ok "${policy:-?}"; fi
    fi
    gtm_diag_conntrack
    printf 'probe\ticmp\t%s\t0\tpeer-public\n' "$remote"
    printf 'probe\ticmp\t%s\t0\tpeer-inner\n' "$inner"
}

gtm_diagnose() {
    local id=$1 tid=${1#gre-tun-}
    if [[ $id =~ ^F[0-9]{6}$ ]]; then gtm_diagnose_connection "$id"
    elif [[ $id == gre-tun-* && $tid =~ ^[0-9]{1,3}$ ]] && gtm_uint "$tid" 1 250; then gtm_diagnose_gre "$tid"
    else gtm_error 'Diagnosis supports connections and GRE tunnels.'; return 2; fi
}
