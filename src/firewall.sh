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

gtm_iptables_render() {
    local family=$1 table=$2 line proto target total remaining probability index
    local -a targets protocols
    printf '*%s\n' "$table"
    case $table in
        nat) printf ':GTM_PRE - [0:0]\n:GTM_POST - [0:0]\n-F GTM_PRE\n-F GTM_POST\n' ;;
        filter) printf ':GTM_FWD - [0:0]\n-F GTM_FWD\n' ;;
        mangle) printf ':GTM_MSS - [0:0]\n-F GTM_MSS\n' ;;
    esac
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        [[ $R_ENGINE == iptables && $R_ENABLED == 1 ]] || continue
        if [[ $family == 4 ]]; then [[ $R_BIND != *:* ]] || continue; else [[ $R_BIND == *:* ]] || continue; fi
        IFS=, read -r -a targets <<< "$R_TARGETS"
        protocols=("$R_PROTO"); [[ $R_PROTO == both ]] && protocols=(tcp udp)
        total=0
        for target in "${targets[@]}"; do gtm_endpoint "$target" || return 1; ((total+=EP_WEIGHT)); done
        for proto in "${protocols[@]}"; do
            remaining=$total; index=0
            for target in "${targets[@]}"; do
                gtm_endpoint "$target" || return 1
                if [[ $table == nat ]]; then
                    printf -- '-A GTM_PRE -d %s' "$R_BIND"
                    [[ $R_IFACE == any ]] || printf ' -i %s' "$R_IFACE"
                    printf ' -p %s --dport %d -m comment --comment gtm-%s' "$proto" "$((10#$R_PORT))" "$R_ID"
                    if (( index < ${#targets[@]}-1 )); then
                        probability=$(awk -v weight="$EP_WEIGHT" -v rest="$remaining" 'BEGIN {printf "%.10f", weight/rest}')
                        printf ' -m statistic --mode random --probability %s' "$probability"
                    fi
                    printf ' -j DNAT --to-destination %s\n' "$(gtm_address "$EP_IP" "$EP_PORT")"
                    if [[ $R_SNAT == masquerade ]]; then
                        printf -- '-A GTM_POST -p %s -d %s --dport %s -m conntrack --ctstate DNAT --ctdir ORIGINAL --ctorigdst %s --ctorigdstport %d -m comment --comment gtm-%s -j MASQUERADE\n' "$proto" "$EP_IP" "$EP_PORT" "$R_BIND" "$((10#$R_PORT))" "$R_ID"
                    fi
                elif [[ $table == filter ]]; then
                    printf -- '-A GTM_FWD -p %s -d %s --dport %s -m conntrack --ctstate DNAT --ctdir ORIGINAL --ctorigdst %s --ctorigdstport %d -m comment --comment gtm-%s -j ACCEPT\n' "$proto" "$EP_IP" "$EP_PORT" "$R_BIND" "$((10#$R_PORT))" "$R_ID"
                    printf -- '-A GTM_FWD -p %s -s %s --sport %s -m conntrack --ctstate ESTABLISHED --ctdir REPLY --ctorigdst %s --ctorigdstport %d -m comment --comment gtm-%s -j ACCEPT\n' "$proto" "$EP_IP" "$EP_PORT" "$R_BIND" "$((10#$R_PORT))" "$R_ID"
                elif [[ $proto == tcp ]]; then
                    printf -- '-A GTM_MSS -p tcp -d %s --dport %s --tcp-flags SYN,RST SYN -m conntrack --ctstate DNAT --ctdir ORIGINAL --ctorigdst %s --ctorigdstport %d -j TCPMSS --clamp-mss-to-pmtu\n' "$EP_IP" "$EP_PORT" "$R_BIND" "$((10#$R_PORT))"
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
        case $table in nat) local -a hooks=(PREROUTING:GTM_PRE POSTROUTING:GTM_POST);; filter) hooks=(FORWARD:GTM_FWD);; mangle) hooks=(FORWARD:GTM_MSS);; esac
        for hook in "${hooks[@]}"; do
            chain=${hook#*:}; hook=${hook%%:*}
            "$tool" -w 5 -t "$table" -C "$hook" -j "$chain" 2>/dev/null || "$tool" -w 5 -t "$table" -I "$hook" 1 -j "$chain" || return 1
        done
    done
}

gtm_nft_render() {
    local line family proto target index total offset end
    local -a targets protocols
    # 'add' existing table is idempotent; a single batch flushes only our table.
    printf 'add table inet gre_manager\nflush table inet gre_manager\n'
    printf 'add chain inet gre_manager pre { type nat hook prerouting priority -105; policy accept; }\n'
    printf 'add chain inet gre_manager post { type nat hook postrouting priority 95; policy accept; }\n'
    printf 'add chain inet gre_manager forward { type filter hook forward priority -5; policy accept; }\n'
    printf 'add chain inet gre_manager mss { type filter hook forward priority -150; policy accept; }\n'
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        [[ $R_ENGINE == nftables && $R_ENABLED == 1 ]] || continue
        family=ip; [[ $R_BIND == *:* ]] && family=ip6
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
            printf 'add rule inet gre_manager pre %s daddr %s' "$family" "$R_BIND"
            [[ $R_IFACE == any ]] || printf ' iifname "%s"' "$R_IFACE"
            printf ' %s dport %d counter ' "$proto" "$((10#$R_PORT))"
            if (( ${#targets[@]} == 1 )); then
                gtm_endpoint "${targets[0]}" || return 1
                printf 'dnat %s to %s' "$family" "$(gtm_address "$EP_IP" "$EP_PORT")"
            else
                printf 'numgen random mod %d vmap { ' "$total"; offset=0; index=0
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
                    printf 'add rule inet gre_manager mss meta l4proto tcp %s daddr %s tcp dport %s ct status dnat ct direction original ct original %s daddr %s ct original proto-dst %d tcp flags & (syn | rst) == syn tcp option maxseg size set rt mtu counter comment "gtm-%s"\n' "$family" "$EP_IP" "$EP_PORT" "$family" "$R_BIND" "$((10#$R_PORT))" "$R_ID"
                fi
                if [[ $R_SNAT == masquerade ]]; then
                    printf 'add rule inet gre_manager post meta l4proto %s %s daddr %s %s dport %s ct status dnat ct original %s daddr %s ct original proto-dst %d counter masquerade comment "gtm-%s"\n' "$proto" "$family" "$EP_IP" "$proto" "$EP_PORT" "$family" "$R_BIND" "$((10#$R_PORT))" "$R_ID"
                fi
                printf 'add rule inet gre_manager forward meta l4proto %s %s daddr %s %s dport %s ct status dnat ct original %s daddr %s ct original proto-dst %d counter accept comment "gtm-%s"\n' "$proto" "$family" "$EP_IP" "$proto" "$EP_PORT" "$family" "$R_BIND" "$((10#$R_PORT))" "$R_ID"
                printf 'add rule inet gre_manager forward meta l4proto %s %s saddr %s %s sport %s ct state established ct direction reply ct original %s daddr %s ct original proto-dst %d counter accept comment "gtm-%s"\n' "$proto" "$family" "$EP_IP" "$proto" "$EP_PORT" "$family" "$R_BIND" "$((10#$R_PORT))" "$R_ID"
            done
        done
    done
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
    # Also clear previously owned chains/tables after disabling/deleting records.
    if (( ipt4 )) || { command -v iptables >/dev/null && iptables -t nat -S GTM_PRE >/dev/null 2>&1; }; then gtm_iptables_apply 4 || return 1; fi
    if (( ipt6 )) || { command -v ip6tables >/dev/null && ip6tables -t nat -S GTM_PRE >/dev/null 2>&1; }; then gtm_iptables_apply 6 || return 1; fi
    if (( nft )) || { command -v nft >/dev/null && nft list table inet gre_manager >/dev/null 2>&1; }; then
        file=$(mktemp "$GTM_RUN_DIR/nft.XXXXXX") || return 1
        gtm_nft_render > "$file" && nft -c -f "$file" && nft -f "$file" || { rm -f "$file"; return 1; }
        rm -f "$file"
    fi
    (( v4 == 0 )) || sysctl -w net.ipv4.ip_forward=1 || return 1
    # Do not silently disable RA on an IPv6 host. Require the operator's routing setup.
    if (( v6 )) && [[ $(sysctl -n net.ipv6.conf.all.forwarding) != 1 ]]; then
        gtm_error 'Enable IPv6 forwarding and preserve Router Advertisements where required, then apply again.'; return 1
    fi
}
