# Port Forward Manager (h-zare-dev/iptables-forward-manager, "portfw"): read its
# saved rules for import and refuse entrance ports its active NAT already owns.
# Its files and tables are never changed here.
gtm_portfw_paths() {
    GTM_PORTFW_DIR=${GTM_PORTFW_DIR:-/etc/iptables-forward-manager}
    GTM_PORTFW_RULES="$GTM_PORTFW_DIR/rules.db"
}

# True while either portfw engine has NAT installed.
gtm_portfw_active() {
    command -v nft >/dev/null 2>&1 && nft list table ip ifm_portfw >/dev/null 2>&1 && return 0
    command -v iptables >/dev/null 2>&1 && iptables -w 2 -t nat -C PREROUTING -j IFM_DNAT >/dev/null 2>&1
}

# Prints "id<TAB>source<TAB>target<TAB>dest<TAB>proto" for each valid saved rule.
gtm_portfw_rules() {
    local line id source target dest proto count=0
    gtm_portfw_paths
    [[ -f $GTM_PORTFW_RULES && ! -L $GTM_PORTFW_RULES ]] || return 0
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -n $line ]] || continue
        IFS='|' read -r id source target dest proto <<< "$line"
        [[ $id =~ ^[0-9]{1,6}$ && $source =~ ^[0-9,\ -]{1,1024}$ && $dest =~ ^[0-9,\ -]{1,1024}$ && $proto =~ ^(tcp|udp|both)$ ]] || continue
        gtm_ipv4 "$target" || gtm_hostname "$target" || continue
        printf '%s\t%s\t%s\t%s\t%s\n' "$id" "${source// /}" "$target" "${dest// /}" "$proto"
        ((++count < 1000)) || break
    done < "$GTM_PORTFW_RULES"
}

# Fails when an active portfw rule already forwards PORT (or span) for PROTOCOL.
gtm_portfw_listener_check() {
    local protocol=$1 bind=$2 port=$3 id source target dest proto word first last
    [[ $bind != *:* ]] || return 0
    gtm_portfw_paths
    [[ -f $GTM_PORTFW_RULES ]] && gtm_port_span "$port" || return 0
    first=$PS_FIRST last=$PS_LAST
    gtm_portfw_active || return 0
    while IFS=$'\t' read -r id source target dest proto; do
        [[ $protocol == both || $proto == both || $protocol == "$proto" ]] || continue
        for word in ${source//,/ }; do
            gtm_port_span "$word" || continue
            (( PS_LAST < first || PS_FIRST > last )) && continue
            gtm_error "Port Forward Manager (portfw) rule $id already forwards $word. Import it under Configuration, then remove it from portfw first."
            return 1
        done
    done < <(gtm_portfw_rules)
    return 0
}
