# Firewall: per-connection access rules and abuse protection in the owned
# nftables table "inet gtm_guard", UFW openings tagged with the connection ID,
# and a read-only report of the host firewall (UFW, firewalld, Docker and both
# iptables backends). Settings live in firewall.tsv. A change can arm an
# automatic revert that a transient systemd timer runs unless it is confirmed,
# so a rule that cuts the operator off undoes itself without the panel.
#
# firewall.tsv (tab separated, one setting per line):
#   protect  private|smtp  0|1      drop new uplink traffic to private ranges / port 25
#   except   CIDR                   private destinations that stay reachable
#   access   ID MODE PERIP RATE CIDRS
#            MODE off|allow|deny for the source list CIDRS (comma separated or -),
#            PERIP concurrent connections per source (0 = off),
#            RATE new connections per second per source (0 = off)
#   ufw      ID                     keep the connection's ports open in UFW
GTM_GUARD_UNIT=gre-manager-firewall-revert
GTM_GUARD_CIDRS_MAX=128
GTM_GUARD_PRIVATE4='10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16'
GTM_GUARD_PRIVATE6='fc00::/7'

gtm_guard_paths() {
    GTM_GUARD_FILE="$GTM_CONFIG_DIR/firewall.tsv"
    GTM_GUARD_PREV="$GTM_CONFIG_DIR/firewall.tsv.revert"
    GTM_GUARD_DEADLINE="$GTM_CONFIG_DIR/firewall.revert-at"
    GTM_GUARD_OPENED="$GTM_CONFIG_DIR/ufw-opened.tsv"
}

# An address or a network with zero host bits; sets GTM_CIDR_FAMILY (4 or 6).
gtm_guard_cidr() {
    local value=$1 address length=-1 max=32 key nibble index bits
    GTM_CIDR_FAMILY=4
    if [[ $value == */* ]]; then
        address=${value%/*}; length=${value##*/}
        [[ $length =~ ^[0-9]{1,3}$ ]] || return 1
        length=$((10#$length))
    else address=$value; fi
    if gtm_ipv4 "$address"; then
        ((length < 0)) && return 0
        ((length >= 1 && length <= 32)) || return 1
        local -a octets; IFS=. read -r -a octets <<< "$address"
        local number=$(( (10#${octets[0]} << 24) | (10#${octets[1]} << 16) | (10#${octets[2]} << 8) | 10#${octets[3]} ))
        (( (number & ((1 << (32 - length)) - 1)) == 0 ))
        return
    fi
    gtm_ipv6 "$address" && gtm_key_of "$address" || return 1
    GTM_CIDR_FAMILY=6 max=128 key=$GTM_KEY
    ((length < 0)) && return 0
    ((length >= 1 && length <= max)) || return 1
    # Every bit after the prefix must be zero.
    for ((index = length / 4; index < 32; index++)); do
        nibble=$((16#${key:index:1}))
        bits=$((length - index * 4))
        if ((bits > 0)); then (( (nibble & ((1 << (4 - bits)) - 1)) == 0 )) || return 1
        else ((nibble == 0)) || return 1; fi
    done
}

# Validates one settings line. Access lines name an existing connection
# when GTM_RECORDS is loaded with it (unknown IDs are rejected).
gtm_guard_line_valid() {
    local line=$1 kind a b c d e extra cidr count=0
    [[ $line != *$'\r'* && $line != *$'\n'* ]] || return 1
    IFS=$'\t' read -r kind a b c d e extra <<< "$line"
    [[ -z $extra ]] || return 1
    case $kind in
        protect) [[ $a =~ ^(private|smtp)$ && $b =~ ^[01]$ && -z $c ]] ;;
        except) [[ -z $b ]] && gtm_guard_cidr "$a" ;;
        ufw) [[ -z $b ]] && gtm_id "$a" ;;
        access)
            gtm_id "$a" && [[ $b =~ ^(off|allow|deny)$ ]] && gtm_uint "$c" 0 100000 && gtm_uint "$d" 0 100000 && [[ -n $e ]] || return 1
            if [[ $e == - ]]; then [[ $b != allow ]]; return; fi
            local -a cidrs; IFS=, read -r -a cidrs <<< "$e"
            [[ $e != ,* && $e != *, && $e != *,,* ]] || return 1
            for cidr in "${cidrs[@]}"; do gtm_guard_cidr "$cidr" || return 1; ((count += 1)); done
            ((count >= 1 && count <= GTM_GUARD_CIDRS_MAX)) ;;
        *) return 1 ;;
    esac
}

# Loads settings into GTM_GUARD_* (missing file = nothing configured).
gtm_guard_load() {
    local source=${1:-$GTM_GUARD_FILE} line kind a b c d e
    GTM_GUARD_PRIVATE=0 GTM_GUARD_SMTP=0
    GTM_GUARD_EXCEPT=()
    declare -gA GTM_GUARD_ACCESS=() GTM_GUARD_UFW=()
    [[ -e $source || -L $source ]] || return 0
    [[ -f $source && ! -L $source && -r $source ]] || { gtm_error "Firewall settings are unreadable: $source"; return 1; }
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -z $line || $line == '#'* ]] && continue
        gtm_guard_line_valid "$line" || { gtm_error "Invalid firewall setting in $source"; return 1; }
        IFS=$'\t' read -r kind a b c d e <<< "$line"
        case $kind in
            protect) if [[ $a == private ]]; then GTM_GUARD_PRIVATE=$b; else GTM_GUARD_SMTP=$b; fi ;;
            except) GTM_GUARD_EXCEPT+=("$a") ;;
            ufw) GTM_GUARD_UFW[$a]=1 ;;
            access) GTM_GUARD_ACCESS[$a]="$b|$c|$d|$e" ;;
        esac
    done < "$source"
}

# Writes the loaded settings in canonical order, dropping connections that no
# longer exist.
gtm_guard_emit() {
    local line id cidr
    local -A known=()
    for line in ${GTM_RECORDS[@]+"${GTM_RECORDS[@]}"}; do known[${line%%$'\t'*}]=1; done
    printf '# Traffic Manager firewall v1\n'
    printf 'protect\tprivate\t%s\nprotect\tsmtp\t%s\n' "$GTM_GUARD_PRIVATE" "$GTM_GUARD_SMTP"
    for cidr in ${GTM_GUARD_EXCEPT[@]+"${GTM_GUARD_EXCEPT[@]}"}; do printf 'except\t%s\n' "$cidr"; done
    for id in $(printf '%s\n' "${!GTM_GUARD_ACCESS[@]}" | LC_ALL=C sort); do
        [[ ${known[$id]+set} ]] || continue
        printf 'access\t%s\t%s\n' "$id" "${GTM_GUARD_ACCESS[$id]//|/$'\t'}"
    done
    for id in $(printf '%s\n' "${!GTM_GUARD_UFW[@]}" | LC_ALL=C sort); do
        [[ ${known[$id]+set} ]] && printf 'ufw\t%s\n' "$id"
    done
    return 0
}

# Interfaces of the default routes (the uplinks abuse protection watches).
gtm_guard_uplinks() {
    command -v ip >/dev/null 2>&1 || return 0
    { ip -o -4 route show default 2>/dev/null; ip -o -6 route show default 2>/dev/null; } |
        awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}' | LC_ALL=C sort -u
}

# Private destinations that must stay reachable through the uplink: the
# default gateways, this host's resolvers and connection destinations.
gtm_guard_auto_exceptions() {
    local line target
    local -a targets=()
    if command -v ip >/dev/null 2>&1; then
        { ip -o -4 route show default 2>/dev/null; ip -o -6 route show default 2>/dev/null; } |
            awk '{for (i = 1; i < NF; i++) if ($i == "via") print $(i + 1)}'
    fi
    gtm_sysdns_paths
    { gtm_sysdns_nameservers "$GTM_RESOLV"; printf '\n'; gtm_sysdns_nameservers "$GTM_RESOLVED_UPSTREAM"; printf '\n'; } | tr ' ' '\n'
    for line in ${GTM_RECORDS[@]+"${GTM_RECORDS[@]}"}; do
        gtm_record_validate "$line" || continue
        [[ $R_ENABLED == 1 ]] || continue
        IFS=, read -r -a targets <<< "$R_TARGETS"
        for target in "${targets[@]}"; do gtm_target "$target" && ((EP_HOST == 0)) && printf '%s\n' "$EP_IP"; done
    done
}

# Prints the auto exceptions that fall inside a private range, one per line.
gtm_guard_private_exceptions() {
    local address
    while IFS= read -r address; do
        [[ -n $address ]] && gtm_ip "$address" || continue
        if [[ $address == *:* ]]; then
            gtm_key_of "$address" && [[ $GTM_KEY == f[cd]* ]] && printf '%s\n' "$address"
        else
            [[ $address =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.) ]] && printf '%s\n' "$address"
        fi
    done < <(gtm_guard_auto_exceptions) | LC_ALL=C sort -u
}

gtm_guard_set_elements() { local IFS=,; printf '%s' "$*" | sed 's/,/, /g'; }

# Renders the owned guard table from the loaded settings and records. The
# batch replaces only this table; with nothing configured it is removed.
gtm_guard_render() {
    local line id mode perip rate cidrs family nfproto entrance match proto cidr created=0 uplinks
    local -a cidr_list=() family_cidrs=() protocols=() except4=() except6=()
    printf 'add table inet gtm_guard\ndelete table inet gtm_guard\n'
    for line in ${GTM_RECORDS[@]+"${GTM_RECORDS[@]}"}; do
        gtm_record_validate "$line" || return 1
        id=$R_ID
        [[ $R_ENABLED == 1 && ${GTM_GUARD_ACCESS[$id]+set} ]] || continue
        IFS='|' read -r mode perip rate cidrs <<< "${GTM_GUARD_ACCESS[$id]}"
        [[ $mode != off || $perip != 0 || $rate != 0 ]] || continue
        if ((created == 0)); then
            created=1
            printf 'add table inet gtm_guard\n'
            # After conntrack (-200), before DNAT (-100): new flows only, both
            # for kernel forwards and for relays listening on this host.
            printf 'add chain inet gtm_guard access { type filter hook prerouting priority -160; policy accept; }\n'
        fi
        family=ip nfproto=ipv4; [[ $R_BIND == *:* ]] && { family=ip6; nfproto=ipv6; }
        if gtm_wildcard "$R_BIND"; then entrance="meta nfproto $nfproto fib daddr type local"
        else entrance="$family daddr $R_BIND"; fi
        [[ $R_IFACE == any ]] || entrance+=" iifname \"$R_IFACE\""
        protocols=("$R_PROTO"); [[ $R_PROTO == both ]] && protocols=(tcp udp)
        family_cidrs=()
        if [[ $cidrs != - ]]; then
            IFS=, read -r -a cidr_list <<< "$cidrs"
            for cidr in "${cidr_list[@]}"; do
                gtm_guard_cidr "$cidr" || return 1
                [[ $GTM_CIDR_FAMILY == "${nfproto: -1}" ]] && family_cidrs+=("$cidr")
            done
        fi
        local type=ipv4_addr; [[ $family == ip6 ]] && type=ipv6_addr
        if [[ $mode != off ]]; then
            printf 'add set inet gtm_guard a_%s { type %s; flags interval; auto-merge;' "$id" "$type"
            ((${#family_cidrs[@]} == 0)) || printf ' elements = { %s };' "$(gtm_guard_set_elements "${family_cidrs[@]}")"
            printf ' }\n'
        fi
        ((rate == 0)) || printf 'add set inet gtm_guard r_%s { type %s; size 65535; flags dynamic,timeout; timeout 1m; }\n' "$id" "$type"
        ((perip == 0)) || printf 'add set inet gtm_guard c_%s { type %s; size 65535; flags dynamic; }\n' "$id" "$type"
        for proto in "${protocols[@]}"; do
            match="$entrance meta l4proto $proto th dport $(gtm_span_text "$R_FIRST" "$R_LAST")"
            case $mode in
                allow) printf 'add rule inet gtm_guard access %s %s saddr != @a_%s counter drop comment "gtm-%s-allow"\n' "$match" "$family" "$id" "$id" ;;
                deny) printf 'add rule inet gtm_guard access %s %s saddr @a_%s counter drop comment "gtm-%s-deny"\n' "$match" "$family" "$id" "$id" ;;
            esac
            ((rate == 0)) || printf 'add rule inet gtm_guard access %s ct state new add @r_%s { %s saddr limit rate over %d/second burst %d packets } counter drop comment "gtm-%s-rate"\n' "$match" "$id" "$family" "$rate" "$rate" "$id"
            ((perip == 0)) || printf 'add rule inet gtm_guard access %s ct state new add @c_%s { %s saddr ct count over %d } counter drop comment "gtm-%s-conn"\n' "$match" "$id" "$family" "$perip" "$id"
        done
    done
    ((GTM_GUARD_PRIVATE || GTM_GUARD_SMTP)) || return 0
    uplinks=$(gtm_guard_uplinks | awk '{printf "%s\"%s\"", (NR > 1 ? ", " : ""), $0}')
    [[ -n $uplinks ]] || { gtm_error 'No default route: abuse protection has no uplink to watch.'; return 0; }
    ((created)) || printf 'add table inet gtm_guard\n'
    # New connections only: replies to clients on private addresses still pass.
    printf 'add chain inet gtm_guard egress_fwd { type filter hook forward priority 0; policy accept; }\n'
    printf 'add chain inet gtm_guard egress_out { type filter hook output priority 0; policy accept; }\n'
    if ((GTM_GUARD_PRIVATE)); then
        for cidr in ${GTM_GUARD_EXCEPT[@]+"${GTM_GUARD_EXCEPT[@]}"} $(gtm_guard_private_exceptions); do
            gtm_guard_cidr "$cidr" || continue
            if [[ $GTM_CIDR_FAMILY == 6 ]]; then except6+=("$cidr"); else except4+=("$cidr"); fi
        done
        printf 'add set inet gtm_guard private4 { type ipv4_addr; flags interval; auto-merge; elements = { %s }; }\n' "$GTM_GUARD_PRIVATE4"
        printf 'add set inet gtm_guard private6 { type ipv6_addr; flags interval; auto-merge; elements = { %s }; }\n' "$GTM_GUARD_PRIVATE6"
        printf 'add set inet gtm_guard except4 { type ipv4_addr; flags interval; auto-merge;'
        ((${#except4[@]} == 0)) || printf ' elements = { %s };' "$(gtm_guard_set_elements "${except4[@]}")"
        printf ' }\nadd set inet gtm_guard except6 { type ipv6_addr; flags interval; auto-merge;'
        ((${#except6[@]} == 0)) || printf ' elements = { %s };' "$(gtm_guard_set_elements "${except6[@]}")"
        printf ' }\n'
        for line in egress_fwd egress_out; do
            printf 'add rule inet gtm_guard %s oifname { %s } ct state new ip daddr @private4 ip daddr != @except4 counter drop comment "gtm-private"\n' "$line" "$uplinks"
            printf 'add rule inet gtm_guard %s oifname { %s } ct state new ip6 daddr @private6 ip6 daddr != @except6 counter drop comment "gtm-private"\n' "$line" "$uplinks"
        done
    fi
    if ((GTM_GUARD_SMTP)); then
        for line in egress_fwd egress_out; do
            printf 'add rule inet gtm_guard %s oifname { %s } ct state new tcp dport 25 counter drop comment "gtm-smtp"\n' "$line" "$uplinks"
        done
    fi
}

# Succeeds when the settings ask for any guard rule at all.
gtm_guard_wanted() {
    local id mode perip rate
    ((GTM_GUARD_PRIVATE || GTM_GUARD_SMTP)) && return 0
    for id in "${!GTM_GUARD_ACCESS[@]}"; do
        IFS='|' read -r mode perip rate _ <<< "${GTM_GUARD_ACCESS[$id]}"
        [[ $mode == off && $perip == 0 && $rate == 0 ]] || return 0
    done
    return 1
}

# Applies the guard table and the UFW openings for the loaded records.
gtm_guard_apply() {
    local file
    gtm_guard_paths
    gtm_guard_load || return 1
    if gtm_guard_wanted; then
        gtm_need nft || return 1
        file=$(mktemp "$GTM_RUN_DIR/guard.XXXXXX") || return 1
        gtm_guard_render > "$file" && nft -c -f "$file" && nft -f "$file" || { rm -f "$file"; gtm_error 'The firewall rules were rejected; previous guard rules stay.'; return 1; }
        rm -f "$file"
    elif command -v nft >/dev/null 2>&1 && nft list table inet gtm_guard >/dev/null 2>&1; then
        nft delete table inet gtm_guard || return 1
    fi
    gtm_guard_ufw_sync
}

# --- UFW -----------------------------------------------------------------

gtm_ufw_present() { command -v ufw >/dev/null 2>&1; }

# "proto port" pairs (port in UFW syntax) a connection listens on.
gtm_guard_ufw_specs() {
    local proto port
    port=$(gtm_span_text "$R_FIRST" "$R_LAST" :)
    for proto in tcp udp; do
        [[ $R_PROTO == "$proto" || $R_PROTO == both ]] && printf '%s %s\n' "$proto" "$port"
    done
}

# Succeeds when an ALLOW rule from anywhere covers PORT (a number or A:B) for
# PROTO in "ufw status" output on stdin.
gtm_ufw_covers() {
    awk -v proto="$1" -v want="$2" '
        BEGIN { split(want, w, ":"); lo = w[1] + 0; hi = (w[2] == "" ? lo : w[2] + 0) }
        $0 !~ /\(v6\)/ {
            a = 0
            for (i = 2; i <= NF; i++) if ($i == "ALLOW") { a = i; break }
            if (!a) next
            f = a + 1; if ($f == "IN") f++
            if ($f != "Anywhere") next
            to = $(a - 1); p = to; q = ""
            if (index(to, "/")) { p = substr(to, 1, index(to, "/") - 1); q = substr(to, index(to, "/") + 1) }
            if (q != "" && q != proto) next
            if (p !~ /^[0-9:,]+$/) next
            n = split(p, parts, ",")
            for (i = 1; i <= n; i++) {
                split(parts[i], r, ":"); a = r[1] + 0; b = (r[2] == "" ? a : r[2] + 0)
                if (a <= lo && hi <= b) { found = 1; exit }
            }
        }
        END { exit !found }'
}

# Opens wanted ports and closes the ones this manager opened that are no
# longer wanted. A port some other rule already opens is never added, so
# closing never removes a rule the operator wrote.
gtm_guard_ufw_sync() {
    local line id proto port status='' tmp result=0
    local -A wanted=() opened=()
    ((${#GTM_GUARD_UFW[@]})) || [[ -s $GTM_GUARD_OPENED ]] || return 0
    for line in ${GTM_RECORDS[@]+"${GTM_RECORDS[@]}"}; do
        gtm_record_validate "$line" || return 1
        [[ $R_ENABLED == 1 && ${GTM_GUARD_UFW[$R_ID]+set} ]] || continue
        while read -r proto port; do wanted["$R_ID $proto $port"]=1; done < <(gtm_guard_ufw_specs)
    done
    if [[ -f $GTM_GUARD_OPENED && ! -L $GTM_GUARD_OPENED ]]; then
        while IFS=$'\t' read -r id proto port; do
            gtm_id "$id" && [[ $proto =~ ^(tcp|udp)$ && $port =~ ^[0-9]+(:[0-9]+)?$ ]] && opened["$id $proto $port"]=1
        done < "$GTM_GUARD_OPENED"
    fi
    for line in "${!opened[@]}"; do
        [[ ${wanted[$line]+set} ]] && continue
        read -r id proto port <<< "$line"
        if gtm_ufw_present; then
            ufw delete allow proto "$proto" to any port "$port" >/dev/null 2>&1 || { gtm_error "Could not close $port/$proto in UFW."; result=1; continue; }
        fi
        unset 'opened[$line]'
    done
    for line in "${!wanted[@]}"; do
        [[ ${opened[$line]+set} ]] && continue
        gtm_ufw_present || { gtm_error 'UFW is not installed; ports were not opened.'; result=1; break; }
        read -r id proto port <<< "$line"
        [[ -n $status ]] || status=$(LC_ALL=C ufw status 2>/dev/null) || status=' '
        gtm_ufw_covers "$proto" "$port" <<< "$status" && continue
        ufw allow proto "$proto" to any port "$port" comment "gtm-$id" >/dev/null || { gtm_error "Could not open $port/$proto in UFW."; result=1; continue; }
        opened[$line]=1
    done
    tmp=$(mktemp "$GTM_GUARD_OPENED.XXXXXX") || return 1
    for line in "${!opened[@]}"; do read -r id proto port <<< "$line"; printf '%s\t%s\t%s\n' "$id" "$proto" "$port"; done | LC_ALL=C sort > "$tmp"
    chmod 600 "$tmp" && mv "$tmp" "$GTM_GUARD_OPENED" || { rm -f "$tmp"; return 1; }
    return "$result"
}

# --- Changes with automatic revert ---------------------------------------

gtm_guard_revision() {
    gtm_guard_paths
    if [[ -f $GTM_GUARD_FILE ]]; then sha256sum "$GTM_GUARD_FILE" | cut -c1-64; else printf 'none\n'; fi
}

# Arms (or re-arms) the revert timer. The first unconfirmed change keeps its
# snapshot, so a revert returns to the last confirmed settings.
gtm_guard_arm() {
    local seconds=$1
    command -v systemd-run >/dev/null 2>&1 || { gtm_error 'systemd-run is needed for an automatic revert.'; return 1; }
    systemctl stop "$GTM_GUARD_UNIT.timer" >/dev/null 2>&1 || true
    systemctl reset-failed "$GTM_GUARD_UNIT.service" >/dev/null 2>&1 || true
    systemd-run --quiet --unit "$GTM_GUARD_UNIT" --on-active="${seconds}s" --timer-property=AccuracySec=1s "$GTM_RUNTIME" --firewall-revert || return 1
    printf '%s\n' "$(($(date +%s) + seconds))" > "$GTM_GUARD_DEADLINE"
}

gtm_guard_disarm() {
    systemctl stop "$GTM_GUARD_UNIT.timer" >/dev/null 2>&1 || true
    rm -f "$GTM_GUARD_PREV" "$GTM_GUARD_DEADLINE"
}

# Stdin: the expected revision, then settings lines. SECONDS > 0 arms a revert.
gtm_guard_change() {
    local seconds=$1 expected line candidate first=0 id
    local -a lines=()
    gtm_uint "$seconds" 0 900 && { ((10#$seconds == 0 || 10#$seconds >= 30)); } || { gtm_error 'The confirmation window must be 30-900 seconds.'; return 2; }
    IFS= read -r expected && [[ $expected =~ ^([a-f0-9]{64}|none)$ ]] || return 2
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -z $line ]] && continue
        lines+=("$line"); ((${#lines[@]} <= 4096)) || return 2
    done
    gtm_prepare && gtm_lock || return 1
    gtm_guard_paths
    [[ $(gtm_guard_revision) == "$expected" ]] || { gtm_error 'Firewall settings changed; reload and try again.'; gtm_unlock; return 1; }
    gtm_load_records || { gtm_unlock; return 1; }
    local -A known=()
    for line in ${GTM_RECORDS[@]+"${GTM_RECORDS[@]}"}; do known[${line%%$'\t'*}]=1; done
    candidate=$(mktemp "$GTM_GUARD_FILE.XXXXXX") || { gtm_unlock; return 1; }
    for line in ${lines[@]+"${lines[@]}"}; do
        gtm_guard_line_valid "$line" || { gtm_error "Invalid firewall setting: ${line//$'\t'/ }"; rm -f "$candidate"; gtm_unlock; return 2; }
        IFS=$'\t' read -r _ id _ <<< "$line"
        if [[ $line == access$'\t'* || $line == ufw$'\t'* ]] && [[ ! ${known[$id]+set} ]]; then
            gtm_error "Connection $id no longer exists; reload and try again."; rm -f "$candidate"; gtm_unlock; return 1
        fi
    done
    printf '%s\n' ${lines[@]+"${lines[@]}"} > "$candidate" && gtm_guard_load "$candidate" || { rm -f "$candidate"; gtm_unlock; return 1; }
    gtm_guard_allow_check || { rm -f "$candidate"; gtm_unlock; return 1; }
    gtm_guard_emit > "$candidate" && chmod 600 "$candidate" || { rm -f "$candidate"; gtm_unlock; return 1; }
    if ((10#$seconds > 0)) && [[ ! -f $GTM_GUARD_PREV ]]; then
        first=1
        if [[ -f $GTM_GUARD_FILE ]]; then cp -p "$GTM_GUARD_FILE" "$GTM_GUARD_PREV"; else printf '# Traffic Manager firewall v1\n' > "$GTM_GUARD_PREV"; fi || { rm -f "$candidate"; gtm_unlock; return 1; }
        chmod 600 "$GTM_GUARD_PREV"
    fi
    local backup=''
    if [[ -f $GTM_GUARD_FILE ]]; then backup=$(mktemp "$GTM_RUN_DIR/firewall.XXXXXX") && cp -p "$GTM_GUARD_FILE" "$backup" || { rm -f "$candidate"; gtm_unlock; return 1; }; fi
    mv "$candidate" "$GTM_GUARD_FILE" || { rm -f "$candidate" "$backup"; gtm_unlock; return 1; }
    if ! gtm_guard_apply; then
        gtm_error 'Firewall change failed; the previous settings were restored.'
        if [[ -n $backup ]]; then mv "$backup" "$GTM_GUARD_FILE"; else rm -f "$GTM_GUARD_FILE"; fi
        ((first == 0)) || rm -f "$GTM_GUARD_PREV"
        gtm_guard_apply || gtm_error 'Firewall recovery needs attention; inspect "nft list table inet gtm_guard".'
        gtm_unlock; return 1
    fi
    rm -f "$backup"
    if ((10#$seconds > 0)); then
        gtm_install_runner && gtm_guard_arm "$((10#$seconds))" || {
            gtm_error 'The automatic revert could not be armed; reverting now.'
            gtm_guard_restore_prev; gtm_unlock; return 1; }
        printf 'Firewall settings applied. Confirm within %d seconds or they revert.\n' "$((10#$seconds))"
    else
        [[ ! -f $GTM_GUARD_PREV ]] || gtm_guard_disarm
        printf 'Firewall settings applied.\n'
    fi
    gtm_unlock
}

# An allow list must admit at least one source of the connection's family.
gtm_guard_allow_check() {
    local line mode cidrs cidr ok
    local -a list=()
    for line in ${GTM_RECORDS[@]+"${GTM_RECORDS[@]}"}; do
        gtm_record_validate "$line" || return 1
        [[ ${GTM_GUARD_ACCESS[$R_ID]+set} ]] || continue
        IFS='|' read -r mode _ _ cidrs <<< "${GTM_GUARD_ACCESS[$R_ID]}"
        [[ $mode == allow ]] || continue
        ok=0; IFS=, read -r -a list <<< "$cidrs"
        for cidr in "${list[@]}"; do
            gtm_guard_cidr "$cidr" || continue
            if [[ $R_BIND == *:* ]]; then [[ $GTM_CIDR_FAMILY == 6 ]] && ok=1
            else [[ $GTM_CIDR_FAMILY == 4 ]] && ok=1; fi
        done
        ((ok)) || { gtm_error "The allow list of $R_ID needs at least one source of the connection's address family."; return 1; }
    done
}

# Caller holds the lock. Puts back the last confirmed settings.
gtm_guard_restore_prev() {
    gtm_guard_paths
    [[ -f $GTM_GUARD_PREV ]] || { printf 'No unconfirmed firewall change.\n'; return 0; }
    cp -p "$GTM_GUARD_PREV" "$GTM_GUARD_FILE" || return 1
    gtm_load_records || return 1
    gtm_guard_apply || { gtm_error 'Reverted settings could not be applied.'; return 1; }
    gtm_guard_disarm
    printf 'Firewall settings reverted to the last confirmed version.\n'
}

gtm_guard_confirm() {
    gtm_guard_paths
    [[ -f $GTM_GUARD_PREV ]] || { printf 'No unconfirmed firewall change.\n'; return 0; }
    gtm_guard_disarm
    printf 'Firewall settings confirmed.\n'
}

# --- Status --------------------------------------------------------------

# The backend name of an iptables command: nf_tables or legacy.
gtm_guard_backend_name() { if "$1" -V 2>/dev/null | grep -q nf_tables; then printf 'nf_tables'; else printf 'legacy'; fi; }

# Read-only report. Lines: "key<TAB>values...". See panel/internal/control/firewall.go.
gtm_guard_status() {
    local family tool policy input status default line id proto port state verbose
    gtm_guard_paths
    gtm_load_records || return 1
    gtm_guard_load || return 1
    printf 'revision\t%s\n' "$(gtm_guard_revision)"
    if command -v nft >/dev/null 2>&1; then printf 'nft\tavailable\n'; else printf 'nft\tmissing\n'; fi
    if [[ -f $GTM_GUARD_PREV && -f $GTM_GUARD_DEADLINE ]]; then printf 'pending\t%s\n' "$(head -n 1 "$GTM_GUARD_DEADLINE")"; fi
    if gtm_guard_wanted; then
        if command -v nft >/dev/null 2>&1 && nft list table inet gtm_guard >/dev/null 2>&1; then printf 'applied\t1\n'; else printf 'applied\t0\n'; fi
    fi
    # UFW: installed, active, default incoming and routed policies.
    if gtm_ufw_present; then
        verbose=$(LC_ALL=C ufw status verbose 2>/dev/null) || verbose=''
        state=inactive; [[ $verbose == *'Status: active'* ]] && state=active
        default=$(awk -F': ' '/^Default:/ {print $2; exit}' <<< "$verbose")
        input=$(sed -n 's/.*\b\([a-z]*\) (incoming).*/\1/p' <<< "$default"); [[ -n $input ]] || input=-
        policy=$(sed -n 's/.*\b\([a-z]*\) (routed).*/\1/p' <<< "$default"); [[ -n $policy ]] || policy=-
        printf 'ufw\t%s\t%s\t%s\n' "$state" "$input" "$policy"
        status=$(LC_ALL=C ufw status 2>/dev/null) || status=''
    else printf 'ufw\tmissing\t-\t-\n'; fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        if systemctl is-active --quiet firewalld 2>/dev/null; then printf 'firewalld\tactive\n'; else printf 'firewalld\tinactive\n'; fi
    fi
    if command -v docker >/dev/null 2>&1 || [[ -e /sys/class/net/docker0 ]]; then printf 'docker\tpresent\n'; fi
    for family in 4 6; do
        while read -r tool policy; do
            input=$("$tool" -w 5 -S INPUT 2>/dev/null | awk '$1 == "-P" {print $3; exit}')
            line=0; "$tool" -w 5 -C FORWARD -j GTM_FWD 2>/dev/null && line=1
            printf 'backend\t%s\t%s\t%s\t%s\t%s\t%s\n' "$family" "$tool" "$(gtm_guard_backend_name "$tool")" "${input:--}" "$policy" "$line"
        done < <(gtm_forward_guards "$family")
    done
    if command -v nft >/dev/null 2>&1; then
        nft list tables 2>/dev/null | awk '$1 == "table" && !($3 == "gre_manager" || $3 == "gtm_guard") {print "table\t" $2 " " $3}'
    fi
    gtm_guard_uplinks | sed 's/^/uplink\t/'
    if command -v ss >/dev/null 2>&1; then
        ss -Hltnp 2>/dev/null | awk '/"sshd"/ {n = split($4, a, ":"); print "ssh\t" a[n]}' | LC_ALL=C sort -u
    fi
    gtm_guard_private_exceptions | sed 's/^/auto-except\t/'
    for line in ${GTM_RECORDS[@]+"${GTM_RECORDS[@]}"}; do
        gtm_record_validate "$line" || return 1
        id=$R_ID
        while read -r proto port; do
            if ! gtm_ufw_present; then state=-
            elif grep -q "# gtm-$id\$" <<< "$status" && gtm_ufw_covers "$proto" "$port" <<< "$status"; then state=tagged
            elif gtm_ufw_covers "$proto" "$port" <<< "$status"; then state=open
            else state=closed; fi
            printf 'port\t%s\t%s\t%s\t%s\n' "$id" "$proto" "$port" "$state"
        done < <(gtm_guard_ufw_specs)
    done
    if command -v nft >/dev/null 2>&1; then
        nft list table inet gtm_guard 2>/dev/null | awk '
            /counter packets/ && /comment "gtm-/ {
                for (i = 1; i <= NF; i++) { if ($i == "packets") p = $(i + 1); if ($i == "bytes") b = $(i + 1); if ($i == "comment") c = $(i + 1) }
                gsub(/"/, "", c); total[c] += p; bytes[c] += b
            }
            END { for (c in total) printf "counter\t%s\t%d\t%d\n", c, total[c], bytes[c] }' | LC_ALL=C sort
    fi
    if [[ -f $GTM_GUARD_FILE ]]; then grep -v '^#' "$GTM_GUARD_FILE" | sed 's/^/setting\t/'; fi
    return 0
}

gtm_guard_api() {
    local operation=$1; shift
    case $operation in
        firewall-status) (($#==0)) && gtm_guard_status ;;
        firewall-apply) (($#==1)) && gtm_guard_change "$1" ;;
        firewall-confirm|firewall-revert) (($#==0)) || return 2
            gtm_prepare && gtm_lock || return 1
            if [[ $operation == firewall-confirm ]]; then gtm_guard_confirm; else gtm_guard_restore_prev; fi
            local result=$?; gtm_unlock; return "$result" ;;
        *) return 2 ;;
    esac
}
