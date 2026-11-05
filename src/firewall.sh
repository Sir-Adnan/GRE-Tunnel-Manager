# Owned chains only. Never flush a host's ruleset or unrelated chains.
gtm_kernel_dependencies() {
    local line
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        [[ $R_ENABLED == 1 ]] || continue
        case $R_ENGINE in
            iptables) gtm_need iptables && gtm_need iptables-restore || return 1
                [[ $R_BIND != *:* ]] || { gtm_need ip6tables && gtm_need ip6tables-restore || return 1; } ;;
            nftables) gtm_need nft || return 1 ;;
        esac
    done
}

# An additional IP with its own gateway uses source policy routing ("from X lookup
# N"). Forwarded replies are routed before un-DNAT restores X as their source, so
# they miss that rule and leave through the main gateway. Flows entering on such
# an address get a connection mark (mask 0xf000000), and owned fwmark rules at
# preference 31001-31015 route their replies through the same table.
# Sets GTM_RT_ADDRS ("family|address|mark|table|interface") and GTM_RT_RULES
# ("family|preference|mark|table"). Route lookups send no packets.
gtm_return_routes_detect() {
    local family probe address iface line table index=0
    local -a found=() names=()
    local -A marks=() seen=()
    GTM_RT_ADDRS=(); GTM_RT_RULES=()
    command -v ip >/dev/null 2>&1 || return 0
    for family in 4 6; do
        probe=1.1.1.1; [[ $family == 4 ]] || probe=2606:4700:4700::1111
        while read -r iface address; do
            address=${address%/*}
            line=$(ip -o -"$family" route get "$probe" from "$address" 2>/dev/null) || continue
            [[ $line =~ \ table\ ([A-Za-z0-9_.-]+)( |$) ]] || continue
            table=${BASH_REMATCH[1]}
            [[ $table != main && $table != local && $table != 254 && $table != 255 ]] || continue
            found+=("$family|$address|$table|$iface")
            [[ ${seen[$table]+set} ]] || { seen[$table]=1; names+=("$table"); }
        done < <(ip -o -"$family" address show scope global 2>/dev/null | awk '{print $2, $4}')
    done
    ((${#found[@]})) || return 0
    # Sorted table names keep marks stable across applies.
    while IFS= read -r table; do
        ((index < 15)) || { gtm_error "More than 15 source routing tables; return routing skips table $table."; continue; }
        index=$((index + 1)); marks[$table]=$(printf '0x%x' "$((index << 24))")
    done < <(printf '%s\n' "${names[@]}" | LC_ALL=C sort -u)
    seen=()
    for line in "${found[@]}"; do
        IFS='|' read -r family address table iface <<< "$line"
        [[ ${marks[$table]+set} ]] || continue
        GTM_RT_ADDRS+=("$family|$address|${marks[$table]}|$table|$iface")
        [[ ${seen[$family|$table]+set} ]] && continue
        seen[$family|$table]=1
        GTM_RT_RULES+=("$family|$((31000 + (${marks[$table]} >> 24)))|${marks[$table]}|$table")
    done
}

# Prints "address mark" for the current record's marked entrance addresses.
gtm_return_marks() {
    local wanted=$1 entry family address mark key=''
    gtm_wildcard "$R_BIND" || { gtm_key_of "$R_BIND" && key=$GTM_KEY; } || return 1
    for entry in ${GTM_RT_ADDRS[@]+"${GTM_RT_ADDRS[@]}"}; do
        IFS='|' read -r family address mark _ <<< "$entry"
        [[ $family == "$wanted" ]] || continue
        if [[ -n $key ]]; then gtm_key_of "$address" && [[ $GTM_KEY == "$key" ]] || continue; fi
        printf '%s %s\n' "$address" "$mark"
    done
}

# Prints each distinct reply mark of one family.
gtm_return_family_marks() {
    local entry family mark
    for entry in ${GTM_RT_RULES[@]+"${GTM_RT_RULES[@]}"}; do
        IFS='|' read -r family _ mark _ <<< "$entry"
        [[ -z $1 || $family == "$1" ]] && printf '%s\n' "$mark"
    done | LC_ALL=C sort -u
}

# Reconcile owned fwmark rules only; foreign rules are never touched.
gtm_return_rules_apply() {
    local family line entry pref mark table
    local -A wanted=()
    for entry in ${GTM_RT_RULES[@]+"${GTM_RT_RULES[@]}"}; do wanted[$entry]=1; done
    command -v ip >/dev/null 2>&1 || { ((${#wanted[@]} == 0)) && return 0; gtm_error 'ip is required for return routing.'; return 1; }
    for family in 4 6; do
        while IFS= read -r line; do
            [[ $line =~ ^(310(0[1-9]|1[0-5])):[[:space:]]+from\ all\ fwmark\ (0x[0-9a-f]+)/0xf000000\ lookup\ ([A-Za-z0-9_.-]+)[[:space:]]*$ ]] || continue
            pref=${BASH_REMATCH[1]}; mark=${BASH_REMATCH[3]}; table=${BASH_REMATCH[4]}
            entry="$family|$pref|$mark|$table"
            if [[ ${wanted[$entry]+set} ]]; then unset 'wanted[$entry]'; continue; fi
            ip -"$family" rule del pref "$pref" fwmark "$mark/0xf000000" lookup "$table" || return 1
        done < <(ip -"$family" rule show 2>/dev/null)
    done
    for entry in "${!wanted[@]}"; do
        IFS='|' read -r family pref mark table <<< "$entry"
        ip -"$family" rule add pref "$pref" fwmark "$mark/0xf000000" lookup "$table" || { gtm_error "Could not add the return route for table $table."; return 1; }
    done
}

# An unspecified bind (0.0.0.0 / ::) matches every address assigned to this host,
# including additional IPs. Explicit binds keep their exact destination match.
# Sets GTM_IPT_ENTRANCE / GTM_IPT_ORIGIN for the current record.
gtm_iptables_scope() {
    if gtm_wildcard "$R_BIND"; then
        GTM_IPT_ENTRANCE='-m addrtype --dst-type LOCAL'; GTM_IPT_ORIGIN=''
    else
        GTM_IPT_ENTRANCE="-d $R_BIND"; GTM_IPT_ORIGIN="--ctorigdst $R_BIND "
    fi
}

gtm_iptables_render() {
    local family=$1 table=$2 line proto target total remaining probability index address mark
    local -a targets protocols
    printf '*%s\n' "$table"
    case $table in
        nat) printf ':GTM_PRE - [0:0]\n:GTM_POST - [0:0]\n-F GTM_PRE\n-F GTM_POST\n' ;;
        filter) printf ':GTM_FWD - [0:0]\n-F GTM_FWD\n' ;;
        mangle) printf ':GTM_MSS - [0:0]\n-F GTM_MSS\n:GTM_RTM - [0:0]\n-F GTM_RTM\n'
            # Replies of marked flows take their entrance address's routing table.
            while read -r mark; do
                printf -- '-A GTM_RTM -m conntrack --ctdir REPLY -m connmark --mark %s/0xf000000 -m comment --comment gtm-return -j MARK --set-xmark %s/0xf000000\n' "$mark" "$mark"
            done < <(gtm_return_family_marks "$family") ;;
    esac
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        [[ $R_ENGINE == iptables && $R_ENABLED == 1 ]] || continue
        if [[ $family == 4 ]]; then [[ $R_BIND != *:* ]] || continue; else [[ $R_BIND == *:* ]] || continue; fi
        IFS=, read -r -a targets <<< "$R_TARGETS"
        protocols=("$R_PROTO"); [[ $R_PROTO == both ]] && protocols=(tcp udp)
        gtm_iptables_scope || return 1
        total=0
        for target in "${targets[@]}"; do gtm_endpoint "$target" || return 1; ((total+=EP_WEIGHT)); done
        for proto in "${protocols[@]}"; do
            remaining=$total; index=0
            for target in "${targets[@]}"; do
                gtm_endpoint "$target" || return 1
                if [[ $table == nat ]]; then
                    if ((index == 0)); then
                        while read -r address mark; do
                            printf -- '-A GTM_PRE -d %s' "$address"
                            [[ $R_IFACE == any ]] || printf ' -i %s' "$R_IFACE"
                            printf ' -p %s --dport %d -m comment --comment gtm-%s -j CONNMARK --set-xmark %s/0xf000000\n' "$proto" "$((10#$R_PORT))" "$R_ID" "$mark"
                        done < <(gtm_return_marks "$family")
                    fi
                    printf -- '-A GTM_PRE %s' "$GTM_IPT_ENTRANCE"
                    [[ $R_IFACE == any ]] || printf ' -i %s' "$R_IFACE"
                    printf ' -p %s --dport %d -m comment --comment gtm-%s' "$proto" "$((10#$R_PORT))" "$R_ID"
                    if (( index < ${#targets[@]}-1 )); then
                        probability=$(awk -v weight="$EP_WEIGHT" -v rest="$remaining" 'BEGIN {printf "%.10f", weight/rest}')
                        printf ' -m statistic --mode random --probability %s' "$probability"
                    fi
                    printf ' -j DNAT --to-destination %s\n' "$(gtm_address "$EP_IP" "$EP_PORT")"
                    if [[ $R_SNAT == masquerade ]]; then
                        printf -- '-A GTM_POST -p %s -d %s --dport %s -m conntrack --ctstate DNAT --ctdir ORIGINAL %s--ctorigdstport %d -m comment --comment gtm-%s -j MASQUERADE\n' "$proto" "$EP_IP" "$EP_PORT" "$GTM_IPT_ORIGIN" "$((10#$R_PORT))" "$R_ID"
                    fi
                elif [[ $table == filter ]]; then
                    printf -- '-A GTM_FWD -p %s -d %s --dport %s -m conntrack --ctstate DNAT --ctdir ORIGINAL %s--ctorigdstport %d -m comment --comment gtm-%s -j ACCEPT\n' "$proto" "$EP_IP" "$EP_PORT" "$GTM_IPT_ORIGIN" "$((10#$R_PORT))" "$R_ID"
                    printf -- '-A GTM_FWD -p %s -s %s --sport %s -m conntrack --ctstate ESTABLISHED --ctdir REPLY %s--ctorigdstport %d -m comment --comment gtm-%s -j ACCEPT\n' "$proto" "$EP_IP" "$EP_PORT" "$GTM_IPT_ORIGIN" "$((10#$R_PORT))" "$R_ID"
                elif [[ $proto == tcp ]]; then
                    printf -- '-A GTM_MSS -p tcp -d %s --dport %s --tcp-flags SYN,RST SYN -m conntrack --ctstate DNAT --ctdir ORIGINAL %s--ctorigdstport %d -j TCPMSS --clamp-mss-to-pmtu\n' "$EP_IP" "$EP_PORT" "$GTM_IPT_ORIGIN" "$((10#$R_PORT))"
                fi
                ((remaining-=EP_WEIGHT)); ((index+=1))
            done
        done
    done
    printf 'COMMIT\n'
}

gtm_iptables_apply() {
    local family=$1 tool=iptables restore=iptables-restore file table chain hook
    [[ $family == 6 ]] && { tool=ip6tables; restore=ip6tables-restore; }
    command -v "$tool" >/dev/null 2>&1 || return 0
    file=$(mktemp "$GTM_RUN_DIR/iptables.XXXXXX") || return 1
    for table in nat filter mangle; do
        gtm_iptables_render "$family" "$table" > "$file" || { rm -f "$file"; return 1; }
        "$restore" -w 5 --noflush --test < "$file" && "$restore" -w 5 --noflush < "$file" || { rm -f "$file"; return 1; }
    done
    rm -f "$file"
    for table in nat filter mangle; do
        case $table in nat) local -a hooks=(PREROUTING:GTM_PRE POSTROUTING:GTM_POST);; filter) hooks=(FORWARD:GTM_FWD);; mangle) hooks=(FORWARD:GTM_MSS PREROUTING:GTM_RTM);; esac
        for hook in "${hooks[@]}"; do
            chain=${hook#*:}; hook=${hook%%:*}
            "$tool" -w 5 -t "$table" -C "$hook" -j "$chain" 2>/dev/null || "$tool" -w 5 -t "$table" -I "$hook" 1 -j "$chain" || return 1
        done
    done
}

gtm_nft_render() {
    local line family number proto target index total offset end entrance origin address mark created=0
    local -a targets protocols
    # One atomic batch replaces only our table. Deleting it (instead of flushing)
    # also removes balancing chains left by deleted records or removed targets.
    # Existing flows keep their conntrack NAT mappings.
    printf 'add table inet gre_manager\ndelete table inet gre_manager\n'
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        [[ $R_ENGINE == nftables && $R_ENABLED == 1 ]] || continue
        if ((created == 0)); then
            created=1
            printf 'add table inet gre_manager\n'
            printf 'add chain inet gre_manager pre { type nat hook prerouting priority -105; policy accept; }\n'
            printf 'add chain inet gre_manager post { type nat hook postrouting priority 95; policy accept; }\n'
            printf 'add chain inet gre_manager forward { type filter hook forward priority -5; policy accept; }\n'
            printf 'add chain inet gre_manager mss { type filter hook forward priority -150; policy accept; }\n'
            # Replies of marked flows take their entrance address's routing table.
            while read -r mark; do
                ((created == 2)) || { created=2; printf 'add chain inet gre_manager rtmark { type filter hook prerouting priority -150; policy accept; }\n'; }
                printf 'add rule inet gre_manager rtmark ct direction reply ct mark and 0xf000000 == %s meta mark set meta mark and 0xf0ffffff or %s comment "gtm-return"\n' "$mark" "$mark"
            done < <(gtm_return_family_marks '')
        fi
        family=ip number=4; [[ $R_BIND == *:* ]] && { family=ip6; number=6; }
        # Unspecified binds match every local address (additional IPs included).
        if gtm_wildcard "$R_BIND"; then
            entrance='meta nfproto ipv4 fib daddr type local'; origin=''
            [[ $family == ip ]] || entrance='meta nfproto ipv6 fib daddr type local'
        else
            entrance="$family daddr $R_BIND"; origin="ct original $family daddr $R_BIND "
        fi
        IFS=, read -r -a targets <<< "$R_TARGETS"
        total=0; for target in "${targets[@]}"; do gtm_endpoint "$target" || return 1; ((total+=EP_WEIGHT)); done
        protocols=("$R_PROTO"); [[ $R_PROTO == both ]] && protocols=(tcp udp)
        for proto in "${protocols[@]}"; do
            if (( ${#targets[@]} > 1 )); then
                index=0
                for target in "${targets[@]}"; do
                    gtm_endpoint "$target" || return 1
                    printf 'add chain inet gre_manager b_%s_%s_%d\n' "$R_ID" "$proto" "$index"
                    printf 'add rule inet gre_manager b_%s_%s_%d meta l4proto %s dnat %s to %s\n' "$R_ID" "$proto" "$index" "$proto" "$family" "$(gtm_address "$EP_IP" "$EP_PORT")"
                    ((index+=1))
                done
            fi
            while read -r address mark; do
                printf 'add rule inet gre_manager pre %s daddr %s' "$family" "$address"
                [[ $R_IFACE == any ]] || printf ' iifname "%s"' "$R_IFACE"
                printf ' %s dport %d ct mark set ct mark and 0xf0ffffff or %s comment "gtm-%s"\n' "$proto" "$((10#$R_PORT))" "$mark" "$R_ID"
            done < <(gtm_return_marks "$number")
            printf 'add rule inet gre_manager pre %s' "$entrance"
            [[ $R_IFACE == any ]] || printf ' iifname "%s"' "$R_IFACE"
            printf ' %s dport %d counter ' "$proto" "$((10#$R_PORT))"
            if (( ${#targets[@]} == 1 )); then
                gtm_endpoint "${targets[0]}" || return 1
                printf 'dnat %s to %s' "$family" "$(gtm_address "$EP_IP" "$EP_PORT")"
            else
                case $R_STRATEGY in
                    source) printf 'jhash %s saddr mod %d seed 0 vmap { ' "$family" "$total";;
                    roundrobin) printf 'numgen inc mod %d vmap { ' "$total";;
                    *) printf 'numgen random mod %d vmap { ' "$total";;
                esac
                offset=0; index=0
                for target in "${targets[@]}"; do
                    gtm_endpoint "$target" || return 1; (( index > 0 )) && printf ', '
                    end=$((offset+EP_WEIGHT-1)); if (( offset == end )); then printf '%d' "$offset"; else printf '%d-%d' "$offset" "$end"; fi
                    printf ' : jump b_%s_%s_%d' "$R_ID" "$proto" "$index"; offset=$((end+1)); ((index+=1))
                done
                printf ' }'
            fi
            printf ' comment "gtm-%s"\n' "$R_ID"
            for target in "${targets[@]}"; do
                gtm_endpoint "$target" || return 1
                if [[ $proto == tcp ]]; then
                    # Match only owned DNAT flows and reduce (never increase) an
                    # existing MSS using the outgoing route's advertised MSS.
                    printf 'add rule inet gre_manager mss meta l4proto tcp %s daddr %s tcp dport %s ct status dnat ct direction original %sct original proto-dst %d tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu counter comment "gtm-%s"\n' "$family" "$EP_IP" "$EP_PORT" "$origin" "$((10#$R_PORT))" "$R_ID"
                fi
                if [[ $R_SNAT == masquerade ]]; then
                    printf 'add rule inet gre_manager post meta l4proto %s %s daddr %s %s dport %s ct status dnat %sct original proto-dst %d counter masquerade comment "gtm-%s"\n' "$proto" "$family" "$EP_IP" "$proto" "$EP_PORT" "$origin" "$((10#$R_PORT))" "$R_ID"
                fi
                printf 'add rule inet gre_manager forward meta l4proto %s %s daddr %s %s dport %s ct status dnat %sct original proto-dst %d counter accept comment "gtm-%s"\n' "$proto" "$family" "$EP_IP" "$proto" "$EP_PORT" "$origin" "$((10#$R_PORT))" "$R_ID"
                printf 'add rule inet gre_manager forward meta l4proto %s %s saddr %s %s sport %s ct state established ct direction reply %sct original proto-dst %d counter accept comment "gtm-%s"\n' "$proto" "$family" "$EP_IP" "$proto" "$EP_PORT" "$origin" "$((10#$R_PORT))" "$R_ID"
            done
        done
    done
}

# Deletes only the tracked flows that one kernel forward DNATed to its own
# targets: original destination port (and address unless the bind is a
# wildcard) plus the target as reply source. Other host flows are untouched.
gtm_flows_reset() {
    local id=$1 line proto target family output count total=0 matched=0
    local -a targets protocols args
    gtm_id "$id" || { gtm_error 'Invalid connection ID.'; return 2; }
    gtm_need conntrack || { printf 'Install conntrack (package conntrack) to reset tracked flows.\n' >&2; return 1; }
    gtm_load_records || return 1
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        [[ $R_ID == "$id" ]] || continue
        matched=1
        [[ $R_ENGINE == nftables || $R_ENGINE == iptables ]] || { gtm_error 'Only kernel forwards keep conntrack mappings.'; return 1; }
        [[ $R_ENABLED == 1 ]] || { gtm_error 'Connection is disabled.'; return 1; }
        family=ipv4; [[ $R_BIND == *:* ]] && family=ipv6
        protocols=("$R_PROTO"); [[ $R_PROTO == both ]] && protocols=(tcp udp)
        IFS=, read -r -a targets <<< "$R_TARGETS"
        for proto in "${protocols[@]}"; do
            for target in "${targets[@]}"; do
                gtm_endpoint "$target" || return 1
                args=(-D -f "$family" -p "$proto" --orig-port-dst "$((10#$R_PORT))" --reply-src "$EP_IP" --reply-port-src "$((10#$EP_PORT))")
                gtm_wildcard "$R_BIND" || args+=(--orig-dst "$R_BIND")
                # conntrack exits non-zero when nothing matched; the count is authoritative.
                output=$(conntrack "${args[@]}" 2>&1 >/dev/null) || true
                if [[ $output =~ ([0-9]+)\ flow\ entries\ have\ been\ deleted ]]; then
                    count=${BASH_REMATCH[1]}; total=$((total + count))
                else
                    gtm_error "conntrack failed: ${output:0:200}"; return 1
                fi
            done
        done
        break
    done
    ((matched)) || { gtm_error 'Connection not found.'; return 1; }
    printf 'Cleared %d tracked flow(s) for %s; clients reconnect on their next packet.\n' "$total" "$id"
}

gtm_kernel_apply() {
    local line v4=0 v6=0 ipt4=0 ipt6=0 nft=0 file
    gtm_load_records && gtm_kernel_dependencies || return 1
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        [[ $R_ENABLED == 1 && ( $R_ENGINE == iptables || $R_ENGINE == nftables ) ]] || continue
        if [[ $R_BIND == *:* ]]; then v6=1; [[ $R_ENGINE == iptables ]] && ipt6=1
        else v4=1; [[ $R_ENGINE == iptables ]] && ipt4=1; fi
        [[ $R_ENGINE == nftables ]] && nft=1
    done
    GTM_RT_ADDRS=(); GTM_RT_RULES=()
    if (( v4 || v6 )); then gtm_return_routes_detect || return 1; fi
    # Also clear previously owned chains/tables after disabling/deleting records.
    if (( ipt4 )) || { command -v iptables >/dev/null && iptables -t nat -S GTM_PRE >/dev/null 2>&1; }; then gtm_iptables_apply 4 || return 1; fi
    if (( ipt6 )) || { command -v ip6tables >/dev/null && ip6tables -t nat -S GTM_PRE >/dev/null 2>&1; }; then gtm_iptables_apply 6 || return 1; fi
    if (( nft )) || { command -v nft >/dev/null && nft list table inet gre_manager >/dev/null 2>&1; }; then
        file=$(mktemp "$GTM_RUN_DIR/nft.XXXXXX") || return 1
        gtm_nft_render > "$file" && nft -c -f "$file" && nft -f "$file" || { rm -f "$file"; return 1; }
        rm -f "$file"
    fi
    gtm_return_rules_apply || return 1
    (( v4 == 0 )) || sysctl -w net.ipv4.ip_forward=1 || return 1
    # Do not silently disable RA on an IPv6 host. Require the operator's routing setup.
    if (( v6 )) && [[ $(sysctl -n net.ipv6.conf.all.forwarding) != 1 ]]; then
        gtm_error 'Enable IPv6 forwarding and preserve Router Advertisements where required, then apply again.'; return 1
    fi
}
