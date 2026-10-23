# Inspection, preflight and dependency checks. No resident monitoring process.
# Used for new reverse listeners: socket checks alone miss kernel DNAT rules.
gtm_port_available() {
    local protocol=$1 bind=$2 port=$3 line key other
    gtm_listener_check "$protocol" "$bind" "$port" && gtm_legacy_listener_check "$protocol" "$bind" "$port" && gtm_load_records || return 1
    key=$(gtm_ip_key "$bind") || return 1
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        [[ $R_ENABLED == 1 ]] && ((10#$R_PORT == 10#$port)) || continue
        [[ $protocol == both || $R_PROTO == both || $protocol == "$R_PROTO" ]] || continue
        other=$(gtm_ip_key "$R_BIND") || return 1
        if [[ $key == "$other" || $key == 0.0.0.0 || $other == 0.0.0.0 || $key == 00000000000000000000000000000000 || $other == 00000000000000000000000000000000 ]]; then
            gtm_error "Port is reserved by managed connection $R_ID ($R_NAME)."; return 1
        fi
    done
    return 0
}

gtm_local_address() {
    local wanted=$1 key address listing
    key=$(gtm_ip_key "$wanted") || return 1
    [[ $key != 0.0.0.0 && $key != 00000000000000000000000000000000 ]] || return 0
    listing=$(ip -o address show) || return 1
    while read -r address; do
        address=${address%/*}
        [[ $(gtm_ip_key "$address") != "$key" ]] || return 0
    done < <(awk '$3 == "inet" || $3 == "inet6" {print $4}' <<< "$listing")
    gtm_error "Entrance IP is not assigned locally: $wanted"
}

gtm_relay_address_key() {
    local key
    key=$(gtm_ip_key "$1") || return 1
    # A hexadecimal IPv4-mapped IPv6 address still connects to an IPv4 socket.
    if [[ ${key:0:24} == 00000000000000000000ffff ]]; then
        printf '%d.%d.%d.%d' "$((16#${key:24:2}))" "$((16#${key:26:2}))" "$((16#${key:28:2}))" "$((16#${key:30:2}))"
    else printf '%s' "$key"; fi
}

# Relays must not loop into their own listener, including mapped address aliases.
gtm_relay_loop_check() {
    local bind_key target address key listing
    local -a fields=() targets=()
    bind_key=$(gtm_relay_address_key "$R_BIND") || return 1
    listing=''
    IFS=, read -r -a targets <<< "$R_TARGETS"
    for target in "${targets[@]}"; do
        gtm_endpoint "$target" || return 1
        ((10#$EP_PORT == 10#$R_PORT)) || continue
        key=$(gtm_relay_address_key "$EP_IP") || return 1
        if [[ $bind_key != 0.0.0.0 && $bind_key != 00000000000000000000000000000000 ]]; then
            [[ $bind_key != "$key" ]] || { gtm_error "Tunnel $R_ID points back to its own listening port."; return 1; }
            continue
        fi
        [[ $bind_key != 0.0.0.0 || $key == *.* ]] || continue
        [[ -n $listing ]] || listing=$(ip -o address show) || return 1
        while read -r -a fields; do
            [[ ${fields[2]:-} == inet || ${fields[2]:-} == inet6 ]] || continue
            address=${fields[3]%/*}
            if [[ $(gtm_relay_address_key "$address") == "$key" ]]; then
                gtm_error "Tunnel $R_ID points back to its own listening port. Choose a different remote port or server."
                return 1
            fi
        done <<< "$listing"
    done
    return 0
}

# Called before replacing desired state. Temporary files contain no executable input.
gtm_preflight_checks() {
    local file=$1 line family table tool has4=0 has6=0 hasnft=0
    gtm_kernel_dependencies || return 1
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        [[ $R_ENABLED == 1 ]] || continue
        gtm_need ip && gtm_local_address "$R_BIND" || return 1
        if [[ $R_ENGINE == haproxy || $R_ENGINE == realm ]]; then gtm_relay_loop_check || return 1; fi
        if [[ $R_ENGINE == iptables || $R_ENGINE == nftables ]]; then
            [[ $R_IFACE == any ]] || ip link show dev "$R_IFACE" >/dev/null || return 1
            if [[ $R_BIND == *:* ]] && [[ $(sysctl -n net.ipv6.conf.all.forwarding) != 1 ]]; then
                gtm_error 'IPv6 forwarding is disabled; configure forwarding and Router Advertisements first.'; return 1
            fi
        fi
        case $R_ENGINE in
            iptables) if [[ $R_BIND == *:* ]]; then has6=1; else has4=1; fi ;;
            nftables) hasnft=1 ;;
            haproxy) [[ $H_ROUTE_MODE != https ]] || gtm_haproxy_certificate >/dev/null || return 1; gtm_need haproxy && gtm_need socat && gtm_need timeout && gtm_haproxy_render > "$file" && haproxy -c -f "$file" || return 1 ;;
            realm) gtm_need realm && gtm_realm_profile_preflight && gtm_realm_render > "$file" || return 1 ;;
        esac
    done
    for family in 4 6; do
        tool=iptables; [[ $family == 4 ]] || tool=ip6tables
        if { [[ $family == 4 ]] && ((has4)); } || { [[ $family == 6 ]] && ((has6)); } ||
            { command -v "$tool" >/dev/null && "$tool" -t nat -S GTM_PRE >/dev/null 2>&1; }; then
            gtm_need "$tool-restore" || return 1
            for table in nat filter mangle; do
                gtm_iptables_render "$family" "$table" > "$file" && "$tool-restore" -w 5 --noflush --test < "$file" || return 1
            done
        fi
    done
    if ((hasnft)) || { command -v nft >/dev/null && nft list table inet gre_manager >/dev/null 2>&1; }; then
        gtm_nft_render > "$file" && nft -c -f "$file" || return 1
    fi
    return 0
}

gtm_preflight() {
    local file result
    file=$(mktemp "$GTM_RUN_DIR/preflight.XXXXXX") || return 1
    gtm_preflight_checks "$file"; result=$?
    rm -f "$file"
    (( result == 0 )) || gtm_error 'Preflight failed. The saved configuration and live services were kept.'
    return "$result"
}

gtm_inspect_state() {
    local file=${1:-$GTM_STATE}
    [[ -f $file && -r $file ]] || { gtm_error "State file is missing or unreadable: $file"; return 1; }
    gtm_load_records "$file" || return 1
    printf 'Valid state: %d connection(s), supported record versions v1/v2/v3/v4.\n' "${#GTM_RECORDS[@]}"
}

# Offline deterministic preview: no root, package installs, temp files or probes.
gtm_plan() {
    local line engine family table has4=0 has6=0 hasnft=0
    gtm_inspect_state "${1:-$GTM_STATE}" || return 1
    printf '\nConfiguration preview / nothing applied\n'
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        printf '\n%s  %s  enabled=%s\n  %s / %s / %s\n  %s -> %s\n' "$R_ID" "$R_NAME" "$R_ENABLED" "$R_ENGINE" "$R_PROTO" "$R_STRATEGY" "$(gtm_address "$R_BIND" "$R_PORT")" "$R_TARGETS"
        [[ $R_ENABLED == 1 ]] || continue
        case $R_ENGINE in
            iptables) if [[ $R_BIND == *:* ]]; then has6=1; else has4=1; fi ;;
            nftables) hasnft=1 ;;
            realm|haproxy) engine=$R_ENGINE; printf '\n# %s %s\n' "$R_ID" "$engine"; "gtm_${engine}_render" || return 1 ;;
        esac
    done
    for family in 4 6; do
        if { [[ $family == 4 ]] && ((has4)); } || { [[ $family == 6 ]] && ((has6)); }; then
            printf '\n# iptables family %s: owned chain contents (parent hooks installed on apply)\n' "$family"
            for table in nat filter mangle; do gtm_iptables_render "$family" "$table" || return 1; done
        fi
    done
    if ((hasnft)); then printf '\n# Native nftables owned table\n'; gtm_nft_render || return 1; fi
    printf '\nPreview excludes host-policy changes, global tuning, old-resource cleanup and FRP/rathole instances.\nOffline validation does not test routing, backend syntax or target health.\n'
}

gtm_doctor() {
    local tool line state used maximum errors=0
    printf 'Traffic Manager %s / read-only health report\n' "$GTM_VERSION"
    printf 'No packets are sent and no settings are changed.\n\n'
    if [[ -e $GTM_STATE || -L $GTM_STATE ]]; then gtm_inspect_state || errors=1
    else GTM_RECORDS=(); printf 'No managed forwarding state yet.\n'; fi
    for tool in ip ss iptables nft realm haproxy socat frpc frps rathole systemctl; do
        if command -v "$tool" >/dev/null 2>&1; then printf '  %-12s %s\n' "$tool" "$(command -v "$tool")"
        else printf '  %-12s unavailable (may be optional)\n' "$tool"; fi
    done
    if [[ $(uname -s) != Linux ]]; then printf '\nLive host checks require Linux.\n'; return "$errors"; fi
    if command -v sysctl >/dev/null; then
        printf '\nIPv4 forwarding: '; sysctl -n net.ipv4.ip_forward 2>/dev/null || printf 'unavailable\n'
        printf 'IPv6 forwarding: '; sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || printf 'unavailable\n'
        used=$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null)
        maximum=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null)
        printf 'Conntrack entries / limit: %s / %s\n' "${used:-unavailable}" "${maximum:-unavailable}"
    fi
    if command -v ip >/dev/null; then
        printf '\nGRE interfaces (includes current MTU):\n'
        ip -d link show type gre; ip -d link show type ip6gre
    fi
    if command -v systemctl >/dev/null; then
        printf '\nManaged relay state (configuration / service):\n'
        for line in "${GTM_RECORDS[@]}"; do
            gtm_record_validate "$line" || continue
            [[ $R_ENGINE == realm || $R_ENGINE == haproxy ]] || continue
            state=$(systemctl is-active "gtm-$R_ID" 2>/dev/null) || :
            printf '  %s  enabled=%s  service=%s\n' "$R_ID" "$R_ENABLED" "${state:-unknown}"
        done
        systemctl list-units 'gtm-frp-*' 'gtm-rathole-*' 'gtm-gateway-*' 'gre-manager-forwarding*' --all --no-pager 2>/dev/null || :
    fi
    printf '\nFor packet drops: check UFW/Docker base-chain policies and return routes.\nFor stalls: inspect path MTU/ICMP; this report does not measure throughput or jitter.\n'
    return "$errors"
}

# Protect known GRE address/interface dependencies, including disabled records.
gtm_link_dependents() {
    local tid=$1 line target key prefix reason
    local -a targets=()
    GTM_DEPENDENTS=()
    gtm_uint "$tid" 1 250 || return 1
    tid=$((10#$tid))
    gtm_load_records || return 1
    prefix=$(gtm_ip_key "fd00:$tid::") || return 1
    prefix=${prefix:0:16}
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        reason=''
        [[ $R_IFACE != "gre$tid" && $R_IFACE != "gre-out-$tid" ]] || reason=interface
        IFS=, read -r -a targets <<< "$R_TARGETS"
        targets+=("$(gtm_address "$R_BIND" "$R_PORT")")
        for target in "${targets[@]}"; do
            gtm_endpoint "$target" || return 1
            key=$(gtm_ip_key "$EP_IP") || return 1
            if [[ $key == "10.0.$tid."[0-3] || ( $EP_IP == *:* && ${key:0:16} == "$prefix" ) ]]; then reason=address; fi
        done
        [[ -z $reason ]] || GTM_DEPENDENTS+=("$R_ID / $R_NAME / $reason")
    done
}

gtm_link_remove_guard() {
    gtm_link_dependents "$1" || return 1
    if (( ${#GTM_DEPENDENTS[@]} )); then
        printf '\nLink is referenced by managed connections:\n'
        printf '  %s\n' "${GTM_DEPENDENTS[@]}"
        gtm_error 'Edit or delete these connections before removing the GRE link (disabled records count too).'
        return 1
    fi
    printf '\nNo known managed dependencies. Check manual/legacy rules and custom routes too.\n'
    gtm_confirm
}
