# Versioned records: v1 has 12 fields, v2 appends validated HAProxy options.
# id name engine protocol bind port strategy enabled snat interface targets version
gtm_record_validate() {
    local line=$1 fields target count=0 family=4 key bind_key
    local -A seen_targets=()
    [[ $line != *$'\r'* && $line != *$'\n'* ]] || return 1
    fields=${line//[^$'\t']/}
    (( ${#fields} == 11 || ${#fields} == 12 || ${#fields} == 13 )) || return 1
    IFS=$'\t' read -r R_ID R_NAME R_ENGINE R_PROTO R_BIND R_PORT R_STRATEGY R_ENABLED R_SNAT R_IFACE R_TARGETS R_VERSION R_OPTIONS R_ROUTING <<< "$line"
    gtm_haproxy_defaults; gtm_realm_defaults; gtm_routing_defaults
    if (( ${#fields} == 11 )); then [[ $R_VERSION == 1 ]] || return 1
    elif (( ${#fields} == 13 )) && [[ $R_VERSION == 4 && $R_ENGINE == haproxy ]]; then
        gtm_haproxy_options_validate "$R_OPTIONS" && gtm_routing_validate "$R_ROUTING" || return 1
    elif (( ${#fields} == 12 )) && [[ $R_VERSION == 2 && $R_ENGINE == haproxy ]]; then gtm_haproxy_options_validate "$R_OPTIONS" || return 1
    elif (( ${#fields} == 12 )) && [[ $R_VERSION == 3 && $R_ENGINE == realm ]]; then gtm_realm_options_validate "$R_OPTIONS" || return 1
    else return 1; fi
    gtm_id "$R_ID" && gtm_name "$R_NAME" && gtm_ip "$R_BIND" && gtm_port "$R_PORT" && gtm_iface "$R_IFACE" || return 1
    [[ $R_ENABLED =~ ^[01]$ && $R_SNAT =~ ^(masquerade|preserve)$ ]] || return 1
    [[ $R_ENGINE =~ ^(iptables|nftables|realm|haproxy)$ && $R_PROTO =~ ^(tcp|udp|both)$ ]] || return 1
    [[ $R_STRATEGY =~ ^(single|random|roundrobin|leastconn|source|failover)$ ]] || return 1
    [[ $R_TARGETS != ,* && $R_TARGETS != *, && $R_TARGETS != *,,* ]] || return 1
    [[ $R_BIND == *:* ]] && family=6
    bind_key=$(gtm_ip_key "$R_BIND") || return 1
    local -a targets
    IFS=, read -r -a targets <<< "$R_TARGETS"
    (( ${#targets[@]} >= 1 && ${#targets[@]} <= 32 )) || return 1
    for target in "${targets[@]}"; do
        gtm_endpoint "$target" || return 1
        if [[ $R_ENGINE == haproxy && $H_CHECK_MODE == http ]] && ((10#$EP_PORT == 10#$H_CHECK_PORT)); then
            gtm_error 'HTTP readiness needs a port different from every traffic destination port.'; return 1
        fi
        key="$(gtm_ip_key "$EP_IP"):$EP_PORT"
        [[ ! ${seen_targets[$key]+set} ]] || return 1
        seen_targets[$key]=1
        # A forward back to its own listener loops or hijacks the relay's socket.
        [[ $key != "$bind_key:$((10#$R_PORT))" ]] || return 1
        if [[ $R_ENGINE == iptables || $R_ENGINE == nftables ]]; then
            [[ $bind_key != 0.0.0.0 && $bind_key != 00000000000000000000000000000000 ]] || return 1
            if (( family == 6 )); then [[ $EP_IP == *:* ]] || return 1; else [[ $EP_IP != *:* ]] || return 1; fi
        fi
        ((count+=1))
    done
    [[ $R_STRATEGY != single || $count == 1 ]] || return 1
    case $R_ENGINE in
        iptables) [[ $R_STRATEGY == single || $R_STRATEGY == random ]] || return 1 ;;
        nftables) [[ $R_STRATEGY =~ ^(single|random|roundrobin|source)$ ]] || return 1 ;;
        realm) [[ $R_STRATEGY == single || $R_STRATEGY == roundrobin || $R_STRATEGY == source ]] && gtm_realm_profile_validate || return 1 ;;
        haproxy) [[ $R_PROTO == tcp && $R_STRATEGY =~ ^(single|roundrobin|leastconn|source|failover)$ ]] || return 1 ;;
    esac
}

gtm_load_records() {
    local source=${1:-$GTM_STATE} line other
    GTM_RECORDS=()
    # Only an absent default state means a new installation. Never reconcile an
    # unreadable file, directory or dangling link as an empty desired state.
    if [[ ! -e $source && ! -L $source && $# == 0 ]]; then return 0; fi
    [[ -f $source && -r $source ]] || { gtm_error "State file is missing, unreadable or not a regular file: $source"; return 1; }
    local -A ids=()
    local bind port iface id bind_key other_key
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -z $line || $line == '#'* ]] && continue
        gtm_record_validate "$line" || { gtm_error "Invalid connection record in $source"; return 1; }
        id=$R_ID; bind=$R_BIND; port=$((10#$R_PORT)); iface=$R_IFACE
        bind_key=$(gtm_ip_key "$bind") || return 1
        [[ ! ${ids[$id]+set} ]] || { gtm_error "Duplicate ID: $id"; return 1; }; ids[$id]=1
        # Reject ambiguous listeners across engines, wildcard binds and interfaces.
        for other in "${GTM_RECORDS[@]}"; do
            local O_ID O_NAME O_ENGINE O_PROTO O_BIND O_PORT O_STRATEGY O_ENABLED O_SNAT O_IFACE O_TARGETS O_VERSION
            IFS=$'\t' read -r O_ID O_NAME O_ENGINE O_PROTO O_BIND O_PORT O_STRATEGY O_ENABLED O_SNAT O_IFACE O_TARGETS O_VERSION <<< "$other"
            [[ $R_ENABLED == 1 && $O_ENABLED == 1 ]] || continue
            (( port == 10#$O_PORT )) || continue
            [[ $R_PROTO == both || $O_PROTO == both || $R_PROTO == "$O_PROTO" ]] || continue
            other_key=$(gtm_ip_key "$O_BIND") || return 1
            [[ $bind_key == "$other_key" || $bind_key == 0.0.0.0 || $other_key == 0.0.0.0 || $bind_key == 00000000000000000000000000000000 || $other_key == 00000000000000000000000000000000 ]] || continue
            # Relays bind sockets, not entrance interfaces. Only kernel rules can
            # safely distinguish identical listeners on two explicit interfaces.
            if [[ $R_ENGINE =~ ^(iptables|nftables)$ && $O_ENGINE =~ ^(iptables|nftables)$ ]]; then
                [[ $iface == any || $O_IFACE == any || $iface == "$O_IFACE" ]] || continue
            fi
            gtm_error "Listener conflicts: $id and $O_ID"; return 1
        done
        GTM_RECORDS+=("$line")
    done < "$source"
}

gtm_new_id() {
    local line id maximum=0 value serial
    if [[ -r $GTM_CONFIG_DIR/id-counter ]]; then
        IFS= read -r serial < "$GTM_CONFIG_DIR/id-counter" || return 1
        gtm_uint "$serial" 0 999999 || { gtm_error 'Invalid ID allocation counter.'; return 1; }
        maximum=$((10#$serial))
    fi
    for line in "${GTM_RECORDS[@]}"; do
        id=${line%%$'\t'*}; value=${id#F}; value=$((10#$value))
        (( value > maximum )) && maximum=$value
    done
    (( maximum < 999999 )) || return 1
    printf 'F%06d' "$((maximum+1))"
}

gtm_write_records() {
    local dest=$1
    { printf '# Traffic Manager records v1/v2/v3/v4\n'; printf '%s\n' "${GTM_RECORDS[@]}"; } > "$dest"
}

gtm_record_emit() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$R_ID" "$R_NAME" "$R_ENGINE" "$R_PROTO" "$R_BIND" "$R_PORT" "$R_STRATEGY" "$R_ENABLED" "$R_SNAT" "$R_IFACE" "$R_TARGETS" "$R_VERSION"
    [[ $R_VERSION == 1 ]] || printf '\t%s' "$R_OPTIONS"
    [[ $R_VERSION != 4 ]] || printf '\t%s' "$R_ROUTING"
    return 0
}

# Caller reloads under lock. Refuse to overwrite another session's completed edit.
gtm_replace_record() {
    local expected=$1 replacement=$2 line found=0
    local id=${expected%%$'\t'*}
    local -a updated=()
    gtm_record_validate "$replacement" && [[ $R_ID == "$id" ]] || return 1
    for line in "${GTM_RECORDS[@]}"; do
        if [[ ${line%%$'\t'*} == "$id" ]]; then
            [[ $line == "$expected" ]] || { gtm_error 'Connection changed in another session. Reopen the editor.'; return 1; }
            updated+=("$replacement"); found=1
        else updated+=("$line"); fi
    done
    ((found)) || { gtm_error 'Connection was removed by another operation.'; return 1; }
    GTM_RECORDS=("${updated[@]}")
}

gtm_selection() {
    local value=$1 max=$2 token index
    local -a tokens=()
    GTM_SELECTED=()
    local -A seen=()
    read -r -a tokens <<< "$value"
    (( ${#tokens[@]} > 0 && ${#tokens[@]} <= max )) || return 1
    for token in "${tokens[@]}"; do
        gtm_uint "$token" 1 "$max" || return 1
        index=$((10#$token-1))
        [[ ${seen[$index]+set} ]] && continue
        seen[$index]=1; GTM_SELECTED+=("$index")
    done
}

gtm_install_runner() {
    local func tmp
    mkdir -p "${GTM_RUNTIME%/*}" || return 1
    tmp=$(mktemp "${GTM_RUNTIME}.XXXXXX") || return 1
    {
        printf '#!/usr/bin/env bash\n# Generated Traffic Manager kernel reconciler.\n'
        printf 'GTM_CONFIG_DIR=%q\nGTM_RUN_DIR=%q\nGTM_SERVICE_DIR=%q\nGTM_RUNTIME=%q\n' "$GTM_CONFIG_DIR" "$GTM_RUN_DIR" "$GTM_SERVICE_DIR" "$GTM_RUNTIME"
        while IFS= read -r func; do declare -f "$func"; done < <(compgen -A function gtm_)
        printf '\ngtm_paths\ngtm_prepare && gtm_lock || exit 1\ngtm_kernel_apply\nresult=$?\ngtm_unlock\nexit "$result"\n'
    } > "$tmp"
    bash -n "$tmp" && chmod 700 "$tmp" && mv "$tmp" "$GTM_RUNTIME" || { rm -f "$tmp"; return 1; }
    cat > "$GTM_SERVICE_DIR/gre-manager-forwarding.service" <<EOF
[Unit]
Description=Traffic Manager owned kernel forwarding rules
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
ExecStart=$GTM_RUNTIME
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable gre-manager-forwarding.service || return 1
}

# Caller holds the manager lock. Restore only owned resources on failure.
gtm_commit() {
    local backup candidate recovery=0
    backup="$GTM_CONFIG_DIR/backups/$(date -u +%Y%m%dT%H%M%S)-$$-$RANDOM.tsv"
    candidate=$(mktemp "$GTM_CONFIG_DIR/state.XXXXXX") || return 1
    gtm_write_records "$candidate" && gtm_load_records "$candidate" || { rm -f "$candidate"; return 1; }
    if ! gtm_preflight; then rm -f "$candidate"; return 1; fi
    if [[ -f $GTM_STATE ]]; then
        cp "$GTM_STATE" "$backup" || { rm -f "$candidate"; return 1; }
    else printf '# Traffic Manager state v1\n' > "$backup" || { rm -f "$candidate"; return 1; }; fi
    chmod 600 "$candidate" "$backup" && mv "$candidate" "$GTM_STATE" || { rm -f "$candidate"; return 1; }
    if gtm_install_runner && gtm_kernel_apply && gtm_relays_apply; then
        printf 'Saved and applied. Restore point: %s\n' "${backup##*/}"
        return 0
    fi
    gtm_error 'Apply failed. Restoring the previous managed configuration.'
    candidate=$(mktemp "$GTM_CONFIG_DIR/recover.XXXXXX") || return 1
    cp "$backup" "$candidate" && chmod 600 "$candidate" && mv "$candidate" "$GTM_STATE" || { rm -f "$candidate"; return 1; }
    gtm_load_records || return 1
    gtm_kernel_apply || recovery=1
    gtm_relays_apply || recovery=1
    if ((recovery)); then
        gtm_error "Recovery needs attention. State restored at $GTM_STATE; check journalctl -u gre-manager-forwarding."
    fi
    return 1
}
