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

# A specific entrance address that is no longer assigned (the server's IP
# changed) never matches; an unspecified bind follows every local address.
gtm_diag_entrance() {
    if gtm_wildcard "$R_BIND"; then gtm_diag entrance ok 'all local addresses'
    elif gtm_local_address "$R_BIND" 2>/dev/null; then gtm_diag entrance ok "$R_BIND"
    else gtm_diag entrance fail "$R_BIND"; fi
}

# Docker and UFW drop forwarded packets by iptables policy, in either backend
# (nf_tables or legacy); an nftables accept cannot override it, so the owned
# iptables accept must be hooked in every backend that drops.
gtm_diag_forward_policy() {
    local family=$1 tool policy dropping='' missing='' seen=0
    while read -r tool policy; do
        seen=1
        [[ $policy == DROP ]] || continue
        dropping+="${dropping:+, }$tool"
        "$tool" -w 5 -C FORWARD -j GTM_FWD 2>/dev/null && "$tool" -w 5 -S GTM_FWD 2>/dev/null | grep -q -- "gtm-$R_ID" || missing+="${missing:+, }$tool"
    done < <(gtm_forward_guards "$family")
    ((seen)) || return 0
    if [[ -z $dropping ]]; then gtm_diag forward-policy ok ACCEPT
    elif [[ -z $missing ]]; then gtm_diag forward-policy ok "DROP ($dropping), owned accept installed"
    else gtm_diag forward-policy fail "DROP ($missing)"; fi
}

# The source address the destination sees: pinned SNAT on a multi-address
# interface, masquerade otherwise, or the client's own address (preserve).
gtm_diag_source() {
    local line=$1 target sources='' source
    local -a targets=()
    if [[ $R_SNAT != masquerade ]]; then gtm_diag source-address info preserve; return; fi
    # Detection walks every record; reload this one afterwards.
    gtm_snat_detect >/dev/null 2>&1 || return 0
    gtm_record_validate "$line" && gtm_resolve_targets 2>/dev/null || return 0
    IFS=, read -r -a targets <<< "$R_TARGETS"
    for target in "${targets[@]:0:4}"; do
        gtm_target "$target" || continue
        source=$(gtm_snat_source "$EP_IP")
        [[ -n $source ]] && sources+="${sources:+, }$EP_IP <- $source"
    done
    if [[ -n $sources ]]; then gtm_diag source-address info "pinned: $sources"
    else gtm_diag source-address info masquerade; fi
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
            gtm_diag_entrance
            [[ $R_ENABLED != 1 ]] || gtm_diag_forward_policy "$family"
            [[ $family != 4 ]] || gtm_diag_source "$line"
            gtm_record_validate "$line" || return 1
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

# Live packet path of one connection, read-only and cheap enough to poll
# while the panel shows it. Output lines:
#   engine<TAB>ENGINE<TAB>ENABLED
#   stage<TAB>KEY<TAB>ADDRESS|-<TAB>PACKETS<TAB>BYTES
#   drop<TAB>BACKEND
# Kernel forwards report their owned rule counters (since the rules were last
# applied): new (flows entering, NAT hook), snat (flows leaving with this
# server's address), out/back (packets to and from each destination) and
# blocked (firewall access rules). The panel shows rates between samples.
# Relays report current socket counts: clients (TCP only; UDP listeners are
# unconnected) and upstream per destination. drop names an iptables backend
# whose FORWARD policy drops this connection's packets without the owned
# accept.
gtm_path_nft() {
    command -v nft >/dev/null 2>&1 || return 0
    nft list table inet gre_manager 2>/dev/null | awk -v tag="comment \"gtm-$1\"" '
        $1 == "chain" { chain = $2; next }
        !index($0, tag) || !index($0, "counter packets") { next }
        {
            p = 0; b = 0; address = "-"; key = ""
            for (i = 1; i < NF; i++) { if ($i == "packets") p = $(i + 1); if ($i == "bytes") b = $(i + 1) }
            if (chain == "pre") key = "new"
            else if (chain == "post") key = "snat"
            else if (chain == "forward") {
                key = index($0, "direction reply") ? "back" : "out"
                field = key == "back" ? "saddr" : "daddr"
                for (i = 1; i < NF; i++) if ($i == field) { address = $(i + 1); break }
            }
            if (key == "") next
            k = key "\t" address; packets[k] += p; bytes[k] += b
        }
        END { for (k in packets) printf "stage\t%s\t%.0f\t%.0f\n", k, packets[k], bytes[k] }' | LC_ALL=C sort
}

gtm_path_iptables() {
    local tool=iptables-save
    [[ $2 == 4 ]] || tool=ip6tables-save
    command -v "$tool" >/dev/null 2>&1 || return 0
    { "$tool" -c -t nat; "$tool" -c -t filter; } 2>/dev/null | awk -v tag="gtm-$1" '
        $2 != "-A" { next }
        {
            hit = 0
            for (i = 3; i < NF; i++) if ($i == "--comment" && ($(i + 1) == tag || $(i + 1) == "\"" tag "\"")) hit = 1
            if (!hit) next
            counts = substr($1, 2, length($1) - 2); split(counts, c, ":")
            address = "-"; key = ""
            if ($3 == "GTM_PRE" && index($0, " -j DNAT")) key = "new"
            else if ($3 == "GTM_POST") key = "snat"
            else if ($3 == "GTM_FWD") {
                key = index($0, "--ctdir REPLY") ? "back" : "out"
                flag = key == "back" ? "-s" : "-d"
                for (i = 3; i < NF; i++) if ($i == flag) { address = $(i + 1); break }
                sub(/\/(32|128)$/, "", address)
            }
            if (key == "") next
            k = key "\t" address; packets[k] += c[1]; bytes[k] += c[2]
        }
        END { for (k in packets) printf "stage\t%s\t%.0f\t%.0f\n", k, packets[k], bytes[k] }' | LC_ALL=C sort
}

gtm_path_drops() {
    local tool policy
    while read -r tool policy; do
        [[ $policy == DROP ]] || continue
        "$tool" -w 5 -C FORWARD -j GTM_FWD 2>/dev/null && "$tool" -w 5 -S GTM_FWD 2>/dev/null | grep -q -- "gtm-$R_ID" || printf 'drop\t%s\n' "$tool"
    done < <(gtm_forward_guards "$1")
}

gtm_path_count() { ss "$1" state established "$2" 2>/dev/null | grep -c . || :; }

gtm_path_relay() {
    local proto flag target address total
    local -a targets=()
    local -A upstream=()
    command -v ss >/dev/null 2>&1 || return 0
    gtm_resolve_targets 2>/dev/null || return 0
    IFS=, read -r -a targets <<< "$R_TARGETS"
    for proto in tcp udp; do
        [[ $R_PROTO == "$proto" || $R_PROTO == both ]] || continue
        flag=-Htn; [[ $proto == tcp ]] || flag=-Hun
        [[ $proto != tcp ]] || printf 'stage\tclients\t-\t%d\t0\n' "$(gtm_path_count "$flag" "( sport >= :$((10#$R_FIRST)) and sport <= :$((10#$R_LAST)) )")"
        for target in "${targets[@]:0:8}"; do
            gtm_target "$target" || continue
            address=$EP_IP; [[ $address != *:* ]] || address="[$address]"
            total=$(gtm_path_count "$flag" "( dst $address and dport >= :$EP_PORT and dport <= :$EP_LAST )")
            upstream[$EP_IP]=$(( ${upstream[$EP_IP]:-0} + total ))
        done
    done
    for address in "${!upstream[@]}"; do printf 'stage\tupstream\t%s\t%d\t0\n' "$address" "${upstream[$address]}"; done | LC_ALL=C sort
}

gtm_path_guard() {
    command -v nft >/dev/null 2>&1 || return 0
    nft list table inet gtm_guard 2>/dev/null | awk -v tag="comment \"gtm-$1-" '
        !index($0, tag) || !index($0, "counter packets") { next }
        { seen = 1; for (i = 1; i < NF; i++) { if ($i == "packets") p += $(i + 1); if ($i == "bytes") b += $(i + 1) } }
        END { if (seen) printf "stage\tblocked\t-\t%.0f\t%.0f\n", p, b }'
}

gtm_connection_path() {
    local id=$1 line found=0 family=4
    [[ $id =~ ^F[0-9]{6}$ ]] || { gtm_error 'Invalid connection ID.'; return 2; }
    gtm_load_records || return 1
    for line in ${GTM_RECORDS[@]+"${GTM_RECORDS[@]}"}; do
        gtm_record_validate "$line" || return 1
        [[ $R_ID == "$id" ]] && { found=1; break; }
    done
    ((found)) || { gtm_error 'Connection not found.'; return 1; }
    [[ $R_BIND != *:* ]] || family=6
    printf 'engine\t%s\t%s\n' "$R_ENGINE" "$R_ENABLED"
    [[ $R_ENABLED == 1 ]] || return 0
    case $R_ENGINE in
        nftables) gtm_path_nft "$id"; gtm_path_drops "$family";;
        iptables) gtm_path_iptables "$id" "$family"; gtm_path_drops "$family";;
        *) gtm_path_relay;;
    esac
    gtm_path_guard "$id"
}
