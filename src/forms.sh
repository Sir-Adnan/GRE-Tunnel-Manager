# Numbered, staged forms. Collection is read-only; saving reloads full state under lock.
gtm_parse_ports() {
    local input=$1 word first last port
    local -a words=()
    local -A seen=()
    GTM_PORTS=()
    [[ -n $input && ${#input} -le 1024 && $input != ,* && $input != *, && $input != *,,* ]] || return 1
    read -r -a words <<< "${input//,/ }"
    for word in "${words[@]}"; do
        if [[ $word =~ ^([0-9]+)-([0-9]+)$ ]]; then first=${BASH_REMATCH[1]}; last=${BASH_REMATCH[2]}
        else first=$word; last=$word; fi
        gtm_port "$first" && gtm_port "$last" || return 1
        first=$((10#$first)); last=$((10#$last))
        ((first<=last && last-first<32)) || return 1
        for ((port=first; port<=last; port++)); do
            [[ ! ${seen[$port]+set} ]] || continue
            GTM_PORTS+=("$port"); seen[$port]=1
            ((${#GTM_PORTS[@]}<=32)) || return 1
        done
    done
    ((${#GTM_PORTS[@]}>0))
}

gtm_ask_port() {
    local label=$1 default=$2 port_input
    while true; do
        gtm_default "$label" port_input "$default" || return 1
        [[ $port_input != 0 ]] || return 1
        if gtm_port "$port_input"; then GTM_REPLY=$((10#$port_input)); return 0; fi
        gtm_error 'Use a port from 1 to 65535. Enter 0 to cancel.'
    done
}

gtm_ask_ip() {
    local label=$1 default=$2 ip_input
    while true; do
        gtm_default "$label" ip_input "$default" || return 1
        [[ $ip_input != 0 ]] || return 1
        if gtm_ip "$ip_input"; then GTM_REPLY=$ip_input; return 0; fi
        gtm_error 'Enter a valid IPv4 or IPv6 address. Enter 0 to cancel.'
    done
}

gtm_form_ports() {
    local input
    gtm_step 1 3 'Local port(s)'
    printf '  Example: 443, 8443 or 8000-8003. Enter 0 to cancel.\n'
    while true; do
        gtm_default 'Local port(s)' input "${W_PORTS[*]:-443}" || return 1
        [[ $input != 0 ]] || return 1
        if gtm_parse_ports "$input"; then
            if [[ -n $W_EDIT && ${#GTM_PORTS[@]} != 1 ]]; then gtm_error 'Edit one port at a time. Use Add tunnel for more ports.'; continue; fi
            W_PORTS=("${GTM_PORTS[@]}"); return 0
        fi
        gtm_error 'Use ports 1-65535; up to 32 ports per setup.'
    done
}

gtm_form_target() {
    local input port_default=$1
    while true; do
        gtm_default 'Remote IP (IP:port also works)' input '' || return 1
        [[ $input != 0 ]] || return 1
        if gtm_ip "$input"; then
            W_REMOTE_IP=$input
            gtm_ask_port 'Remote port' "$port_default" || return 1
            W_REMOTE_PORT=$GTM_REPLY; W_REMOTE_WEIGHT=1; return 0
        elif gtm_endpoint "$input"; then
            W_REMOTE_IP=$EP_IP; W_REMOTE_PORT=$EP_PORT; W_REMOTE_WEIGHT=$EP_WEIGHT; return 0
        fi
        gtm_error 'Enter a valid IP or IP:port. IPv6 with a port: [2001:db8::1]:443.'
    done
}

gtm_form_targets() {
    local count=0 key family='' current_family
    local -A seen=()
    gtm_step 2 3 'Remote server'
    if [[ -n $W_TARGETS ]]; then
        printf '  Current: %s\n' "$W_TARGETS"
        gtm_choose 'Remote server' keep 'Keep current' keep 'Change' change || return 1
        [[ $GTM_REPLY != keep ]] || return 0
    fi
    W_TARGETS=''
    while true; do
        gtm_form_target "${W_PORTS[0]}" || return 1
        current_family=4; [[ $W_REMOTE_IP != *:* ]] || current_family=6
        if [[ $W_ENGINE == iptables || $W_ENGINE == nftables ]]; then
            if [[ -n $family && $family != "$current_family" ]]; then gtm_error 'Use the same IP version for all kernel targets.'; continue; fi
            family=$current_family
        fi
        key="$(gtm_ip_key "$W_REMOTE_IP"):$W_REMOTE_PORT"
        if [[ ${seen[$key]+set} ]]; then gtm_error 'That server and port are already in the list.'; continue; fi
        seen[$key]=1
        W_TARGETS+="${W_TARGETS:+,}$(gtm_address "$W_REMOTE_IP" "$W_REMOTE_PORT")@$W_REMOTE_WEIGHT"
        ((count+=1))
        [[ $W_MODE == balance && $count -lt 32 ]] || break
        if ((count<2)); then printf '\n  Add the second server.\n'; continue; fi
        gtm_choose 'Remote servers' 'done' 'Continue' 'done' 'Add another server' add || return 1
        [[ $GTM_REPLY == add ]] || break
    done
    if [[ $W_ENGINE != haproxy ]]; then
        gtm_choose 'Protocol' "$W_PROTO" TCP tcp UDP udp 'TCP + UDP' both || return 1
        W_PROTO=$GTM_REPLY
    fi
    if [[ $W_TARGETS == *,* ]]; then
        case $W_ENGINE in
            haproxy) gtm_choose 'Load balancing' "$W_STRATEGY" 'Round robin' roundrobin 'Least connections' leastconn 'Same client, same server' source 'Primary / backup' failover || return 1; W_STRATEGY=$GTM_REPLY;;
            realm) gtm_choose 'Load balancing' "$W_STRATEGY" 'Round robin' roundrobin 'Same client, same server' source || return 1; W_STRATEGY=$GTM_REPLY;;
            nftables) gtm_choose 'Load balancing' "$W_STRATEGY" 'Weighted random' random 'Round robin (new flows)' roundrobin 'Same source IP, same server' source || return 1; W_STRATEGY=$GTM_REPLY;;
            *) W_STRATEGY=random;;
        esac
    else W_STRATEGY=single; fi
    if ((${#W_PORTS[@]}>1)); then
        gtm_choose 'Remote ports' one 'Use the remote port(s) entered above' one 'Use the same port number as local' same || return 1
        W_MAP=$GTM_REPLY
    fi
}

# A route lookup sends no packets. Prefer the primary address, not a GRE address.
gtm_suggest_bind() {
    local family=$1 probe=1.1.1.1 listing index address
    local -a fields=()
    [[ $family != 6 ]] || probe=2001:4860:4860::8888
    listing=$(ip -"$family" route get "$probe" 2>/dev/null) || listing=''
    read -r -a fields <<< "$listing"
    for index in "${!fields[@]}"; do
        if [[ ${fields[$index]} == src && $((index+1)) -lt ${#fields[@]} ]]; then
            address=${fields[$((index+1))]}
            if gtm_ip "$address"; then printf '%s' "$address"; return 0; fi
        fi
    done
    listing=$(ip -o -"$family" address show scope global 2>/dev/null) || return 1
    while read -r -a fields; do
        [[ ${fields[1]:-} != gre* && ${fields[1]:-} != ip6gre* ]] || continue
        address=${fields[3]:-}; address=${address%/*}
        if gtm_ip "$address"; then printf '%s' "$address"; return 0; fi
    done <<< "$listing"
    return 1
}

gtm_form_bind() {
    local value family=4 first=${W_TARGETS%%,*}
    if [[ $W_ENGINE == haproxy || $W_ENGINE == realm ]]; then W_BIND=${W_BIND:-0.0.0.0}; return 0; fi
    gtm_endpoint "$first" || return 1
    [[ $EP_IP != *:* ]] || family=6
    if [[ -n $W_BIND ]] && { [[ $family == 6 && $W_BIND != *:* ]] || [[ $family == 4 && $W_BIND == *:* ]]; }; then W_BIND=''; fi
    [[ -n $W_BIND ]] || W_BIND=$(gtm_suggest_bind "$family") || :
    while true; do
        if gtm_ip "$W_BIND" && [[ $W_BIND != 0.0.0.0 && $W_BIND != :: ]] &&
            { [[ $family == 4 && $W_BIND != *:* ]] || [[ $family == 6 && $W_BIND == *:* ]]; }; then return 0; fi
        printf '  Use a specific local IPv%s address for this forward.\n' "$family"
        gtm_ask_ip 'Local IP' '' || return 1
        value=$GTM_REPLY
        W_BIND=$value
    done
}

gtm_form_advanced() {
    local selection input current
    while true; do
        gtm_header "$W_TITLE / Optional settings"
        gtm_option 1 'Tunnel name' "$W_NAME"
        gtm_option 2 'Listen address' "$W_BIND"
        [[ $W_ENGINE != iptables && $W_ENGINE != nftables ]] || gtm_option 3 'Client IP / interface'
        [[ $W_ENGINE == haproxy ]] || gtm_option 4 Protocol "$W_PROTO"
        gtm_option 0 'Back to review'
        gtm_read 'Select option' selection || return 1
        case $selection in
            0) return 0;;
            1) while true; do
                   gtm_default 'Name (optional)' input "$W_NAME" || return 1
                   if gtm_name "$input"; then W_NAME=$input; break; fi
                   gtm_error 'Use up to 40 letters, digits, spaces, dot, dash or underscore.'
               done;;
            2)
                if [[ $W_ENGINE == haproxy || $W_ENGINE == realm ]]; then
                    current=$W_BIND
                    [[ $current == 0.0.0.0 || $current == :: ]] || current=custom
                    gtm_choose 'Listen on' "$current" 'All IPv4 addresses' 0.0.0.0 'Specific local IP' custom 'All IPv6 addresses' :: || continue
                    if [[ $GTM_REPLY != custom ]]; then W_BIND=$GTM_REPLY; continue; fi
                fi
                gtm_ask_ip 'Local IP' "$W_BIND" || continue
                W_BIND=$GTM_REPLY
                gtm_form_bind || return 1;;
            3)
                [[ $W_ENGINE == iptables || $W_ENGINE == nftables ]] || continue
                gtm_choose 'Client IP' "$W_SNAT" 'Normal forwarding' masquerade 'Keep client IP (requires return route)' preserve || continue
                W_SNAT=$GTM_REPLY
                current=custom; [[ $W_IFACE != any ]] || current=any
                gtm_choose 'Network interface' "$current" 'All interfaces' any 'Specific interface' custom || continue
                if [[ $GTM_REPLY == any ]]; then W_IFACE=any
                else
                    gtm_default 'Interface name (example: eth0)' input "$W_IFACE" || return 1
                    if gtm_iface "$input"; then W_IFACE=$input; else gtm_error 'Invalid interface name.'; fi
                fi;;
            4) [[ $W_ENGINE != haproxy ]] || continue
                gtm_choose Protocol "$W_PROTO" TCP tcp UDP udp 'TCP + UDP' both || continue
                W_PROTO=$GTM_REPLY;;
        esac
    done
}

gtm_form_rows() {
    local port target targets name
    local -a destinations=()
    GTM_FORM_ROWS=()
    IFS=, read -r -a destinations <<< "$W_TARGETS"
    for port in "${W_PORTS[@]}"; do
        targets=$W_TARGETS
        if [[ $W_MAP == same ]]; then
            targets=''
            for target in "${destinations[@]}"; do
                gtm_endpoint "$target" || return 1
                targets+="${targets:+,}$(gtm_address "$EP_IP" "$port")@$EP_WEIGHT"
            done
        fi
        name=$W_NAME
        if ((${#W_PORTS[@]}>1)); then
            if [[ $W_NAME == "$W_ENGINE-${W_PORTS[0]}" ]]; then name="$W_ENGINE-$port"
            else name="${W_NAME:0:32}-$port"; fi
        fi
        local row
        row=$(printf 'F000000\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$name" "$W_ENGINE" "$W_PROTO" "$W_BIND" "$port" "$W_STRATEGY" "$W_ENABLED" "$W_SNAT" "$W_IFACE" "$targets" "$W_VERSION")
        [[ $W_VERSION == 1 ]] || row+=$'\t'"$W_OPTIONS"
        [[ $W_VERSION != 4 ]] || row+=$'\t'"$W_ROUTING"
        gtm_record_validate "$row" || { gtm_error 'Check the address family, ports and destinations.'; return 1; }
        GTM_FORM_ROWS+=("$row")
    done
}

gtm_form_save() {
    local line id result=1 last_id
    gtm_prepare && gtm_install_component "$W_ENGINE" || return 1
    for line in "${GTM_FORM_ROWS[@]}"; do
        gtm_record_validate "$line" || return 1
        gtm_legacy_listener_check "$R_PROTO" "$R_BIND" "$R_PORT" || return 1
        if [[ $R_ENABLED == 1 && ( -z $W_EDIT || $R_BIND != "$W_OLD_BIND" || $R_PORT != "$W_OLD_PORT" || $R_PROTO != "$W_OLD_PROTO" ) ]]; then
            gtm_listener_check "$R_PROTO" "$R_BIND" "$R_PORT" || return 1
        fi
    done
    gtm_lock || return 1
    if ! gtm_load_records; then gtm_unlock; return 1; fi
    for line in "${GTM_FORM_ROWS[@]}"; do
        if [[ -n $W_EDIT ]]; then
            line="$W_EDIT${line#F000000}"
            gtm_replace_record "$W_ORIGINAL" "$line" || { gtm_unlock; return 1; }
        else
            id=$(gtm_new_id) || { gtm_unlock; return 1; }
            line="$id${line#F000000}"
            GTM_RECORDS+=("$line"); last_id=$id
        fi
    done
    if [[ -n $last_id ]]; then
        printf '%d\n' "$((10#${last_id#F}))" > "$GTM_CONFIG_DIR/id-counter.tmp" && mv "$GTM_CONFIG_DIR/id-counter.tmp" "$GTM_CONFIG_DIR/id-counter" || { gtm_unlock; return 1; }
    fi
    gtm_commit; result=$?
    gtm_unlock
    return "$result"
}

gtm_new_forward() {
    local W_ENGINE=${1:-iptables} W_EDIT=${2:-} W_MODE=${3:-single} W_TITLE line target choice result
    local W_NAME='' W_BIND='' W_TARGETS='' W_PROTO=tcp W_STRATEGY=single W_ENABLED=1 W_SNAT=masquerade W_IFACE=any W_VERSION=1 W_OPTIONS='' W_ROUTING='' W_MAP=one
    local W_ORIGINAL='' W_OLD_BIND='' W_OLD_PORT='' W_OLD_PROTO=''
    local W_REMOTE_IP W_REMOTE_PORT W_REMOTE_WEIGHT
    local -a W_PORTS=() review_targets=()
    case $W_ENGINE in haproxy) W_TITLE=HAProxy; W_SNAT=preserve;; realm) W_TITLE=Realm; W_SNAT=preserve;; *) W_TITLE='Port Forwarding';; esac
    if [[ -n $W_EDIT ]]; then
        gtm_records || return 1
        for line in "${GTM_RECORDS[@]}"; do
            gtm_record_validate "$line" || return 1
            [[ $R_ID == "$W_EDIT" ]] || continue
            W_ORIGINAL=$line; W_NAME=$R_NAME; W_BIND=$R_BIND; W_PORTS=("$R_PORT"); W_TARGETS=$R_TARGETS
            W_PROTO=$R_PROTO; W_STRATEGY=$R_STRATEGY; W_ENABLED=$R_ENABLED; W_SNAT=$R_SNAT; W_IFACE=$R_IFACE; W_VERSION=$R_VERSION; W_OPTIONS=$R_OPTIONS; W_ROUTING=$R_ROUTING
            W_OLD_BIND=$R_BIND; W_OLD_PORT=$R_PORT; W_OLD_PROTO=$R_PROTO
            [[ $R_TARGETS != *,* ]] || W_MODE=balance
        done
        [[ -n $W_ORIGINAL ]] || { gtm_error 'Tunnel no longer exists.'; return 1; }
    fi
    gtm_header "$W_TITLE / $([[ -n $W_EDIT ]] && printf 'Edit tunnel' || printf 'Add tunnel')"
    gtm_form_ports && gtm_form_targets && gtm_form_bind || return 1
    W_NAME=${W_NAME:-$W_ENGINE-${W_PORTS[0]}}
    while true; do
        gtm_header "$W_TITLE / Review"
        gtm_step 3 3 'Review & create'
        gtm_form_rows || return 1
        for line in "${GTM_FORM_ROWS[@]}"; do
            gtm_record_validate "$line" || return 1
            IFS=, read -r -a review_targets <<< "$R_TARGETS"
            for target in "${review_targets[@]}"; do
                gtm_endpoint "$target" || return 1
                gtm_panel_wrap "Local $R_PORT  ->  $(gtm_address "$EP_IP" "$EP_PORT")"
                ((EP_WEIGHT==1)) || gtm_panel_wrap "  Target weight: $EP_WEIGHT"
            done
        done
        printf '\n  Name: %s\n  Protocol: %s\n' "$W_NAME" "${W_PROTO^^}"
        if [[ $W_BIND == 0.0.0.0 ]]; then printf '  Listen on: all IPv4 addresses\n'
        elif [[ $W_BIND == :: ]]; then printf '  Listen on: all IPv6 addresses\n'
        else printf '  Listen on: %s\n' "$W_BIND"; fi
        printf '  State: %s\n\n' "$([[ $W_ENABLED == 1 ]] && printf Enabled || printf Disabled)"
        [[ $W_TARGETS != *,* ]] || printf '  Balance: %s\n\n' "$W_STRATEGY"
        if [[ $W_ENGINE == iptables || $W_ENGINE == nftables ]]; then
            [[ $W_SNAT != preserve ]] || printf '  Client IP preserved / return route required\n'
            [[ $W_IFACE == any ]] || printf '  Interface: %s\n' "$W_IFACE"
        fi
        gtm_option 1 'Save & apply'
        gtm_option 2 'Change local ports'
        gtm_option 3 'Change remote server'
        gtm_option 4 'Optional settings' 'Name / listen address'
        gtm_option 0 Cancel
        gtm_read 'Select option' choice || return 1
        case $choice in
            1) gtm_form_save; result=$?; gtm_pause; return "$result";;
            2) gtm_form_ports || return 1;;
            3) gtm_form_targets && gtm_form_bind || return 1;;
            4) gtm_form_advanced || return 1;;
            0) return 0;;
            *) gtm_error 'Choose a number from the menu.';;
        esac
    done
}
