# The UI asks about tasks; backends handle resources. No packet processing here.
gtm_demo_records() {
    GTM_RECORDS=(
        $'F000001\tReality service\tiptables\ttcp\t192.0.2.10\t443\tsingle\t1\tmasquerade\tany\t10.0.10.1:443@1\t1'
        $'F000002\tWireGuard entrance\tnftables\tudp\t192.0.2.10\t51820\tsingle\t1\tmasquerade\tany\t203.0.113.20:51820@1\t1'
        $'F000003\tTwo destinations\thaproxy\ttcp\t192.0.2.10\t8443\tleastconn\t0\tpreserve\tany\t203.0.113.20:443@2,203.0.113.21:443@1\t1'
    )
}

gtm_records() {
    if [[ ${GTM_DEMO:-0} == 1 ]]; then gtm_demo_records; else gtm_load_records || return; fi
    [[ -n ${GTM_ENGINE_FILTER:-} ]] || return 0
    local row
    local -a matching=()
    for row in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$row" || return 1
        case "$GTM_ENGINE_FILTER:$R_ENGINE" in
            kernel:iptables|kernel:nftables|haproxy:haproxy|realm:realm) matching+=("$row");;
        esac
    done
    GTM_RECORDS=("${matching[@]}")
}

gtm_show_records() {
    local line index=0 state
    gtm_records || return 1
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        ((index+=1)); state=Disabled; [[ $R_ENABLED == 1 ]] && state=Enabled
        printf '\n'
        gtm_connection_card "$index" "$state"
    done
    (( index > 0 )) || printf '\n  Nothing added yet. Choose Add to get started.\n'
    printf '\n  Enabled is configuration state, not a reachability test.\n'
}

gtm_listener_check() {
    local protocol=$1 bind=$2 port=$3 flag listing address key wanted
    local -a fields=()
    command -v ss >/dev/null 2>&1 || return 0
    wanted=$(gtm_ip_key "$bind") || return 1
    for flag in -t -u; do
        [[ $protocol != tcp || $flag == -t ]] || continue
        [[ $protocol != udp || $flag == -u ]] || continue
        listing=$(ss -H -n -l "$flag" "( sport = :$port )") || { gtm_error 'Could not inspect local listeners.'; return 1; }
        while read -r -a fields; do
            (( ${#fields[@]} >= 4 )) || continue
            address=${fields[3]%:*}; address=${address#\[}; address=${address%\]}; address=${address%%%*}
            if [[ $address == '*' ]]; then key='*'; else key=$(gtm_ip_key "$address") || { gtm_error 'Unknown local listener address.'; return 1; }; fi
            if [[ $key == "$wanted" || $key == '*' || $wanted == 0.0.0.0 || $key == 0.0.0.0 || $wanted == 00000000000000000000000000000000 || $key == 00000000000000000000000000000000 ]]; then
                gtm_error "A local service already uses the requested address/port: $bind:$port"; return 1
            fi
        done <<< "$listing"
    done
    return 0
}

gtm_legacy_listener_check() {
    local protocol=$1 bind=$2 port=$3 file line
    local -a words=()
    for file in "$FW_SCRIPT" /opt/simple_gre_script.sh; do
        [[ -r $file ]] || continue
        while IFS= read -r line; do
            read -r -a words <<< "$line"
            [[ ${#words[@]} == 13 && ${words[0]} =~ ^(iptables|ip6tables)$ && ${words[1]} == -t && ${words[2]} == nat && ${words[3]} == -A && ${words[4]} == PREROUTING && ${words[5]} == -p && ${words[7]} == --dport && ${words[9]} == -j && ${words[10]} == DNAT && ${words[11]} == --to-destination ]] || continue
            if [[ $bind == *:* ]]; then [[ ${words[0]} == ip6tables ]] || continue; else [[ ${words[0]} == iptables ]] || continue; fi
            [[ $protocol == both || $protocol == "${words[6]}" ]] || continue
            gtm_port "${words[8]}" || continue
            ((10#${words[8]} == 10#$port)) || continue
            gtm_error "An existing legacy forward already uses this entrance port. Manage it under Legacy forwarding first."
            return 1
        done < "$file"
    done
    return 0
}

gtm_new_forward() {
    local engine=${1:-iptables} name protocol bind port strategy targets='' target snat iface line id edit_id=${2:-} old advanced
    local old_name='' old_proto=tcp old_bind='' old_port='' old_targets='' old_strategy='' old_snat=masquerade old_iface=any old_enabled=1 original='' found=0 old_version=1 old_options=''
    if [[ -n $edit_id ]]; then
        gtm_records || return
        for old in "${GTM_RECORDS[@]}"; do
            gtm_record_validate "$old" || return
            [[ $R_ID == "$edit_id" ]] || continue
            old_name=$R_NAME; old_proto=$R_PROTO; old_bind=$R_BIND; old_port=$R_PORT; old_targets=$R_TARGETS; old_strategy=$R_STRATEGY; old_snat=$R_SNAT; old_iface=$R_IFACE; found=1
            old_enabled=$R_ENABLED; original=$old
            old_version=$R_VERSION; old_options=$R_OPTIONS
        done
        ((found)) || { gtm_error 'Connection no longer exists.'; return; }
    fi
    gtm_header 'Add / edit tunnel or forward'
    gtm_help forward
    printf '  Engine: %s\n' "$engine"
    if [[ $engine == realm || $engine == haproxy ]]; then gtm_help relay; printf '  A relay opens new outgoing connections; it does not retain client source IP.\n'; fi
    gtm_default 'Name' name "$old_name" || return
    if [[ $engine == haproxy ]]; then protocol=tcp
    else gtm_default 'Protocol [tcp/udp/both]' protocol "$old_proto" || return; fi
    gtm_default 'Local IP (this server)' bind "$old_bind" || return
    gtm_default 'Local port' port "$old_port" || return
    gtm_help targets
    [[ -z $old_targets ]] || printf '  Current destinations: %s\n  Empty first line keeps these destinations.\n' "$old_targets"
    while true; do
        gtm_read 'Destination IP:port[@weight]: ' target || return
        [[ -n $target ]] || break
        gtm_endpoint "$target" || { gtm_error 'Invalid destination. IPv6 format: [fd00::1]:443@1'; continue; }
        targets+="${targets:+,}$target"
    done
    targets=${targets:-$old_targets}
    strategy=single
    if [[ $targets == *,* ]]; then
        [[ $old_strategy != single ]] || old_strategy=''
        gtm_help load
        case $engine in
            iptables|nftables) printf '  Strategy: weighted-random (new connections; no health checks).\n'; strategy=random ;;
            realm) gtm_default 'Balance [roundrobin/source]' strategy "${old_strategy:-roundrobin}" || return ;;
            haproxy) gtm_default 'Balance [roundrobin/leastconn/source/failover]' strategy "${old_strategy:-roundrobin}" || return ;;
        esac
    fi
    snat=preserve; iface=any
    if [[ $engine == iptables || $engine == nftables ]]; then
        snat=$old_snat; iface=$old_iface
        gtm_default 'Advanced settings? [y/N]' advanced n || return
        if [[ $advanced == y || $advanced == Y ]]; then
            printf '  Preserve requires a return route on the target server.\n'
            gtm_default 'Client IP [masquerade/preserve]' snat "$old_snat" || return
            gtm_default 'Network interface (any = all)' iface "$old_iface" || return
        fi
    fi
    line=$(printf 'F000000\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$name" "$engine" "$protocol" "$bind" "$port" "$strategy" "$old_enabled" "$snat" "$iface" "$targets" "$old_version")
    [[ $old_version != 2 ]] || line+=$'\t'"$old_options"
    gtm_record_validate "$line" || { gtm_error 'Invalid settings or unsupported protocol/balance combination.'; gtm_pause; return; }
    printf '\n  %s / %s / %s\n  %s:%s -> %s\n' "$name" "$engine" "$protocol" "$bind" "$port" "$targets"
    printf '  Existing connections may be interrupted when applying relay changes.\n'
    printf '  Enabled: %s | Source: %s | Interface: %s\n' "$old_enabled" "$snat" "$iface"
    gtm_confirm || return
    gtm_prepare && gtm_install_component "$engine" || return
    gtm_legacy_listener_check "$protocol" "$bind" "$port" || return
    if [[ $old_enabled == 1 ]] && [[ -z $edit_id || $bind != "$old_bind" || $port != "$old_port" || $protocol != "$old_proto" ]]; then gtm_listener_check "$protocol" "$bind" "$port" || return; fi
    gtm_lock || return
    if ! gtm_load_records; then gtm_unlock; return 1; fi
    if [[ -n $edit_id ]]; then
        line="$edit_id${line#F000000}"
        gtm_replace_record "$original" "$line" || { gtm_unlock; return 1; }
    else
        id=$(gtm_new_id) || { gtm_unlock; return 1; }
        # Allocate under lock; consumed IDs are never reused, even after delete/restore.
        printf '%d\n' "$((10#${id#F}))" > "$GTM_CONFIG_DIR/id-counter.tmp" && mv "$GTM_CONFIG_DIR/id-counter.tmp" "$GTM_CONFIG_DIR/id-counter" || { gtm_unlock; return 1; }
        line="$id${line#F000000}"
        GTM_RECORDS+=("$line")
    fi
    gtm_commit; local result=$?
    gtm_unlock; gtm_pause
    return "$result"
}

gtm_edit_forward() {
    local choice line id engine
    gtm_show_records || return
    (( ${#GTM_RECORDS[@]} > 0 )) || return
    gtm_read 'Edit row [0 cancels]: ' choice || return
    gtm_uint "$choice" 1 "${#GTM_RECORDS[@]}" || return
    line=${GTM_RECORDS[$((10#$choice-1))]}
    gtm_record_validate "$line" || return
    id=$R_ID; engine=$R_ENGINE
    gtm_new_forward "$engine" "$id"
}

gtm_mutate_selected() {
    local operation=$1 selection line index id enabled
    local -a selected_ids=() updated=()
    gtm_show_records || return
    (( ${#GTM_RECORDS[@]} > 0 )) || return
    if [[ $operation == delete ]]; then gtm_help delete
    else printf '\n  Select the rows to %s.\n' "$operation"; fi
    gtm_read 'Rows (example: 1 3 4; empty cancels): ' selection || return
    [[ -n $selection ]] || return
    gtm_selection "$selection" "${#GTM_RECORDS[@]}" || { gtm_error 'Choose valid row numbers.'; return; }
    for index in "${GTM_SELECTED[@]}"; do line=${GTM_RECORDS[$index]}; selected_ids+=("${line%%$'\t'*}"); done
    printf '\n  Action: %s\n  Connection IDs: %s\n  Keep network links and unrelated firewall rules.\n' "$operation" "${selected_ids[*]}"
    gtm_confirm && gtm_prepare && gtm_lock || return
    if ! gtm_load_records; then gtm_unlock; return 1; fi
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || { gtm_unlock; return 1; }
        if [[ " ${selected_ids[*]} " == *" $R_ID "* ]]; then
            [[ $operation != delete ]] || continue
            enabled=0; [[ $operation == enable ]] && enabled=1
            R_ENABLED=$enabled; line=$(gtm_record_emit)
        fi
        updated+=("$line")
    done
    GTM_RECORDS=("${updated[@]}")
    gtm_commit; local result=$?
    gtm_unlock; gtm_pause
    return "$result"
}

gtm_restore_menu() {
    local file choice index=0
    local -a files=()
    gtm_header 'Restore managed forwarding'
    for file in "$GTM_CONFIG_DIR"/backups/*.tsv; do
        [[ -f $file ]] || continue
        files+=("$file"); ((index+=1)); printf '  [%d] %s\n' "$index" "${file##*/}"
    done
    ((index>0)) || { printf 'No restore points.\n'; return; }
    gtm_read 'Restore row [0 cancels]: ' choice || return
    gtm_uint "$choice" 1 "$index" || return
    file=${files[$((10#$choice-1))]}
    gtm_plan "$file" || return
    printf 'This replaces managed forwarding with %s. Existing sessions may end.\n' "${file##*/}"
    gtm_confirm && gtm_prepare && gtm_lock || return
    if gtm_load_records "$file"; then gtm_commit; fi
    gtm_unlock; gtm_pause
}

gtm_forward_menu() {
    local choice GTM_ENGINE_FILTER=kernel
    while true; do
        gtm_header 'Port Forwarding'
        printf '\n  Forward a port to another server. GRE is optional.\n\n'
        gtm_option 1 'Add iptables forward' 'TCP / UDP'
        gtm_option 2 'Add nftables forward' 'TCP / UDP'
        gtm_option 3 'Show forwards'
        gtm_option 4 'Edit forward'
        gtm_option 5 'Delete forward' 'Select one or more'
        gtm_option 6 'Enable / disable'
        gtm_option 7 'Old forwarding rules' 'Rules from v13.x'
        gtm_option 0 Back
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_new_forward iptables;; 2) gtm_new_forward nftables;;
            3) gtm_show_records; gtm_pause;; 4) gtm_edit_forward;;
            5) gtm_mutate_selected delete;; 6) gtm_toggle_menu;; 7) gtm_legacy_forward_menu;;
            0) return;; *) gtm_error 'Choose one of the shown options.';;
        esac
    done
}

gtm_toggle_menu() {
    local choice
    gtm_header 'Enable / disable'
    gtm_option 1 Enable; gtm_option 2 Disable; gtm_option 0 Back
    gtm_read 'Choose: ' choice || return
    case $choice in 1) gtm_mutate_selected enable;; 2) gtm_mutate_selected disable;; esac
}

gtm_engine_menu() {
    local engine=$1 title=$2 choice GTM_ENGINE_FILTER=$1
    while true; do
        gtm_header "$title Tunnel"
        gtm_option 1 'Add tunnel'
        gtm_option 2 'Show tunnels'
        gtm_option 3 'Edit tunnel'
        gtm_option 4 'Delete tunnel'
        gtm_option 5 'Enable / disable'
        [[ $engine != haproxy ]] || gtm_option 6 'Tunnel settings' 'Timeouts / health checks / status'
        gtm_option 0 Back
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_new_forward "$engine";; 2) gtm_show_records; gtm_pause;;
            3) gtm_edit_forward;; 4) gtm_mutate_selected delete;; 5) gtm_toggle_menu;;
            6) [[ $engine != haproxy ]] || gtm_haproxy_settings;;
            0) return;; *) gtm_error 'Choose one of the shown options.';;
        esac
    done
}

gtm_gre_create() {
    local role=$1 result
    gtm_prepare && gtm_lock || return
    if install_deps; then detect_local_ips; setup_tunnel "$role"; result=$?; else result=1; fi
    gtm_unlock
    return "$result"
}

gtm_links_menu() {
    local choice
    while true; do
        gtm_header 'GRE Tunnel'
        gtm_option 1 'Kharej Server' 'Create GRE tunnel'
        gtm_option 2 'Iran Server' 'Create GRE tunnel'
        gtm_option 3 'Show GRE tunnels'
        gtm_option 4 'Delete GRE tunnel'
        gtm_option 5 'Edit GRE config'
        gtm_option 6 'Simple GRE' 'GRE + port forwarding'
        gtm_option 7 'Delete Simple GRE'
        gtm_option 0 Back
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_gre_create kharej;; 2) gtm_gre_create iran;;
            3) if [[ ${GTM_DEMO:-0} == 1 ]]; then printf 'gre-out-10 / GRE / 10.0.10.2 / sample\n'; else ip -d link show type gre; ip -d link show type ip6gre; fi; gtm_pause;;
            4|5|6|7)
                gtm_prepare && gtm_lock || return
                case $choice in 4) remove_tunnel;; 5) edit_tunnel;; 6) if install_deps; then setup_simple_gre; fi;; 7) remove_simple_gre;; esac
                gtm_unlock;;
            0) return;; *) gtm_error 'Choose one of the shown options.';;
        esac
    done
}

gtm_diagnostics() {
    gtm_header 'Diagnostics / read on demand'
    if [[ ${GTM_DEMO:-0} == 0 ]]; then
        gtm_doctor
        printf '\n  Routing rules:\n'; ip rule show
        printf '\n  Legacy rules file: '; [[ ! -f $FW_SCRIPT ]] || printf '%s\n' "$FW_SCRIPT"
    else
        printf 'Demo: read-only host report is available with --doctor.\n'
    fi
    printf '\n  With nftables, an ACCEPT in this table cannot override a DROP\n  in another base chain. Check UFW / Docker forwarding policies.\n'
    printf '  Kernel balancing has no health checks. Use HAProxy for checked TCP failover.\n'
    gtm_pause
}

gtm_legacy_forward_menu() {
    local choice
    gtm_header 'Existing v13.x forwarding'
    printf '  Keep old and new listeners on different IP/port/protocol tuples.\n'
    gtm_option 1 'Add legacy forward'
    gtm_option 2 'Inspect legacy file' 'Read only; never replay unknown shell commands'
    gtm_option 3 'Delete legacy group' 'TCP and UDP grouped by entrance + destination'
    gtm_option 0 Back
    gtm_read 'Choose: ' choice || return
    [[ $choice != 0 ]] || return
    gtm_prepare && gtm_lock || return
    case $choice in 1) setup_advanced_forwarding;; 2) edit_advanced_rules;; 3) gtm_legacy_delete_group;; esac
    gtm_unlock
}

# Strictly recognize generator-owned legacy DNAT syntax. Unknown/manual lines stay.
gtm_legacy_delete_group() {
    local line cmd localport dest choice index=0 key file deleted=0 failed=0
    local -a keys=() lines=() keep=() args=()
    local -A seen=()
    [[ -f $FW_SCRIPT ]] || { printf 'No legacy rules file.\n'; return; }
    mapfile -t lines < "$FW_SCRIPT"
    for line in "${lines[@]}"; do
        read -r -a args <<< "$line"
        # The normal generated line has 13 words, including the destination.
        [[ ${#args[@]} == 13 && ${args[0]} =~ ^(iptables|ip6tables)$ && ${args[1]} == -t && ${args[2]} == nat && ${args[3]} == -A && ${args[4]} == PREROUTING && ${args[5]} == -p && ${args[6]} =~ ^(tcp|udp)$ && ${args[7]} == --dport && ${args[9]} == -j && ${args[10]} == DNAT && ${args[11]} == --to-destination ]] || continue
        gtm_port "${args[8]}" && gtm_endpoint "${args[12]}" || continue
        key="${args[0]}|${args[8]}|${args[12]}"
        [[ ${seen[$key]+set} ]] && continue
        seen[$key]=1; keys+=("$key"); ((index+=1)); printf '  [%d] %s -> %s (%s)\n' "$index" "${args[8]}" "${args[12]}" "${args[0]}"
    done
    ((index>0)) || { printf 'No recognized generated groups. Manual rules were kept.\n'; return; }
    gtm_read 'Delete group row [0 cancels]: ' choice || return
    gtm_uint "$choice" 1 "$index" || return
    key=${keys[$((10#$choice-1))]}; IFS='|' read -r cmd localport dest <<< "$key"
    gtm_need "$cmd" && "$cmd" -t nat -S PREROUTING >/dev/null || return 1
    gtm_endpoint "$dest" || return
    local dest_ip=$EP_IP dest_port=$EP_PORT proto shared=0 other other_cmd other_port other_dest
    for other in "${keys[@]}"; do
        [[ $other != "$key" ]] || continue
        IFS='|' read -r other_cmd other_port other_dest <<< "$other"
        [[ $other_cmd != "$cmd" || $other_dest != "$dest" ]] || shared=1
    done
    printf 'Remove both TCP/UDP forwarding for :%s -> %s\n' "$localport" "$dest"
    gtm_confirm || return
    cp "$FW_SCRIPT" "$GTM_CONFIG_DIR/backups/legacy-$(date -u +%Y%m%dT%H%M%S)-$$.sh" || return
    for line in "${lines[@]}"; do
        local owned=0
        for proto in tcp udp; do
            if [[ $line == "$cmd -t nat -A PREROUTING -p $proto --dport $localport -j DNAT --to-destination $dest" ]]; then owned=1; fi
            if ((shared==0)) && [[ $line == "$cmd -t nat -A POSTROUTING -d $dest_ip -p $proto --dport $dest_port -j MASQUERADE" || $line == "$cmd -I FORWARD -d $dest_ip -p $proto --dport $dest_port -j ACCEPT" ]]; then owned=1; fi
        done
        if ((owned)); then
            read -r -a args <<< "$line"
            for index in "${!args[@]}"; do [[ ${args[$index]} != -A && ${args[$index]} != -I ]] || { args[$index]=-D; break; }; done
            # Check existence, then require deletion to succeed; drain duplicates.
            local -a check=("${args[@]}")
            for index in "${!check[@]}"; do [[ ${check[$index]} != -D ]] || { check[$index]=-C; break; }; done
            while "$cmd" "${check[@]:1}" 2>/dev/null; do
                "$cmd" "${args[@]:1}" || { failed=1; break; }
                ((deleted+=1)); ((deleted<10000)) || { failed=1; break; }
            done
        else keep+=("$line"); fi
    done
    ((failed==0)) || { gtm_error 'Too many duplicate rules; configuration kept for inspection.'; return; }
    file=$(mktemp "${FW_SCRIPT}.XXXXXX") || return
    printf '%s\n' "${keep[@]}" > "$file" && chmod 700 "$file" && mv "$file" "$FW_SCRIPT"
    printf 'Removed legacy group and its duplicates.\n'
}

gtm_home() {
    gtm_header 'Main Menu'
    [[ ${GTM_LANGUAGE:-en} != fa && ${GTM_LANGUAGE:-en} != finglish ]] || gtm_help welcome
    printf '\n'
    gtm_option 1 'GRE Tunnel' 'Create / show / delete'
    gtm_option 2 'Port Forwarding' 'iptables / nftables'
    gtm_option 3 'HAProxy Tunnel' 'TCP tunnel'
    gtm_option 4 'Realm Tunnel' 'TCP / UDP tunnel'
    gtm_option 5 'Reverse Tunnel' 'FRP / rathole'
    gtm_option 6 'Load Balancing' 'Use more than one server'
    gtm_option 7 'Settings & Tools' 'Theme / backup / help'
    gtm_option 0 Exit
    gtm_panel_end
}

gtm_tools_menu() {
    local choice
    while true; do
        gtm_header 'Settings & Tools'
        gtm_option 1 'Appearance & language'
        gtm_option 2 'Server status'
        gtm_option 3 'Backup / restore' 'All managed forwards and relays'
        gtm_option 4 'Install / update igre'
        gtm_option 5 Performance
        gtm_option 6 Cleanup 'Old rules / Simple GRE'
        gtm_option 7 Help 'Which tunnel should I use?'
        gtm_option 8 'Old menu' 'Original options 1-14'
        gtm_option 9 'Show configuration'
        gtm_option 0 Back
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_settings;; 2) gtm_diagnostics;; 3) gtm_restore_menu;;
            4|5|6)
                gtm_prepare && gtm_lock || return
                case $choice in 4) gtm_update_shortcut;; 5) gtm_tuning_menu;; 6) gtm_legacy_cleanup_menu;; esac
                gtm_unlock;;
            7) gtm_catalog; gtm_pause;; 8) gtm_legacy_menu;; 0) return;;
            9) if [[ ${GTM_DEMO:-0} == 1 ]]; then printf 'Use --plan --state-file FILE to inspect a saved configuration.\n'; else gtm_plan; fi; gtm_pause;;
            *) gtm_error 'Choose one of the shown options.';;
        esac
    done
}

gtm_load_menu() {
    local choice
    gtm_header 'Load Balancing'
    gtm_help load
    gtm_option 1 iptables 'TCP / UDP; no health checks'
    gtm_option 2 nftables 'TCP / UDP; no health checks'
    gtm_option 3 HAProxy 'TCP; health checks and failover'
    gtm_option 4 Realm 'TCP / UDP'
    gtm_option 5 FRP 'Reverse TCP tunnel'
    gtm_option 0 Back
    gtm_read 'Choose: ' choice || return
    case $choice in 1) gtm_new_forward iptables;; 2) gtm_new_forward nftables;; 3) gtm_new_forward haproxy;; 4) gtm_new_forward realm;; 5) gtm_frp_menu;; esac
}

gtm_modern_menu() {
    local choice
    while true; do
        gtm_home
        gtm_read 'Choose: ' choice || return 0
        case $choice in
            1) gtm_links_menu;; 2) gtm_forward_menu;; 3) gtm_engine_menu haproxy HAProxy;;
            4) gtm_engine_menu realm Realm;; 5) gtm_reverse_menu;; 6) gtm_load_menu;;
            7) gtm_tools_menu;; 0) printf '%b' "$GTM_RESET"; return;;
            *) gtm_error 'Choose one of the shown options.';;
        esac
    done
}

gtm_legacy_menu() {
    local choice
    while true; do
        gtm_header 'Legacy menu / original numbers'
        gtm_option 1 'GRE side A (Kharej)'; gtm_option 2 'GRE side B (Iran)'
        gtm_option 3 'Delete GRE'; gtm_option 4 'Edit GRE service'
        gtm_option 5 'Install / update shortcut'; gtm_option 6 'Refresh IP cache'
        gtm_option 7 'Simple GRE'; gtm_option 8 'Delete Simple GRE'
        gtm_option 9 'Legacy forwarding'; gtm_option 10 'Inspect legacy rules'
        gtm_option 11 'Delete legacy group'; gtm_option 12 'Legacy cleanup' 'Preview recognized resources; preserve unknown rules'
        gtm_option 13 'Legacy Realm'; gtm_option 14 Performance
        gtm_option 15 'Modern menu'; gtm_option 0 Back
        gtm_read 'Choose: ' choice || return
        case $choice in 0|15) return;; esac
        gtm_prepare && gtm_lock || return
        case $choice in
            1) detect_local_ips; setup_tunnel kharej;; 2) detect_local_ips; setup_tunnel iran;;
            3) remove_tunnel;; 4) edit_tunnel;; 5) gtm_update_shortcut;;
            6) rm -f "$CACHE_V4" "$CACHE_V6" "$CACHE_V4_MISS" "$CACHE_V6_MISS";;
            7) setup_simple_gre;; 8) remove_simple_gre;; 9) setup_advanced_forwarding;; 10) edit_advanced_rules;;
            11) gtm_legacy_delete_group;; 12) wipe_all_gre_configs;; 13) run_realm_menu;; 14) run_perf_menu;;
        esac
        gtm_unlock
    done
}

gtm_update_shortcut() {
    local tmp
    tmp=$(mktemp "${SHORTCUT_PATH}.XXXXXX") || return 1
    curl --proto '=https' --tlsv1.2 -fL --connect-timeout 15 --max-time 120 "$REPO_URL" -o "$tmp" && bash -n "$tmp" && chmod 755 "$tmp" && mv "$tmp" "$SHORTCUT_PATH" || { rm -f "$tmp"; return 1; }
    printf 'Shortcut updated. Run igre again to load the new version.\n'
}

gtm_main() {
    local legacy=0 preview='' theme='' language='' layout='' action='' state_file='' status_id=''
    GTM_DEMO=0
    gtm_paths; gtm_preferences
    while (( $# )); do
        case $1 in
            --help|-h) printf 'Traffic Manager %s\nUsage: bash gre.sh [--legacy] [--demo] [--preview home|forwards]\n  [--theme dark|light|plain] [--language en|finglish|fa]\n  [--layout guided|compact]\nRead only (no root required when files are readable):\n  --validate | --plan [--state-file PATH]\n  --doctor | --catalog | --haproxy-status F000001\n' "$GTM_VERSION"; return;;
            --version) printf 'v%s\n' "$GTM_VERSION"; return;;
            --legacy) legacy=1;; --demo) GTM_DEMO=1;;
            --validate|--plan|--doctor|--catalog) [[ -z $action ]] || { gtm_error 'Choose one inspection action.'; return 2; }; action=${1#--};;
            --haproxy-status) [[ -z $action && $# -ge 2 ]] && gtm_id "$2" || return 2; action=haproxy-status; status_id=$2; shift;;
            --state-file) (( $#>=2 )) && [[ -n $2 ]] || return 2; state_file=$2; shift;;
            --preview) (( $#>=2 )) || return 2; preview=$2; shift;;
            --theme) (( $#>=2 )) || return 2; case $2 in dark|light|plain) theme=$2;; *) return 2;; esac; shift;;
            --layout) (( $#>=2 )) || return 2; case $2 in guided|compact) layout=$2;; *) return 2;; esac; shift;;
            --language) (( $#>=2 )) || return 2; case $2 in en|finglish|fa) language=$2;; *) return 2;; esac; shift;;
            *) gtm_error "Unknown argument: $1"; return 2;;
        esac
        shift
    done
    [[ -z $theme ]] || GTM_THEME=$theme
    [[ -z $layout ]] || GTM_LAYOUT=$layout
    [[ -z $language ]] || GTM_LANGUAGE=$language
    gtm_palette
    if [[ -n $state_file && $action != validate && $action != plan ]]; then gtm_error '--state-file requires --validate or --plan.'; return 2; fi
    if [[ -n $action ]]; then
        [[ -z $preview && $legacy == 0 ]] || { gtm_error 'Inspection actions cannot be combined with menus or UI previews.'; return 2; }
        case $action in
            validate) gtm_inspect_state "${state_file:-$GTM_STATE}";;
            plan) gtm_plan "${state_file:-$GTM_STATE}";;
            doctor) gtm_doctor;;
            catalog) gtm_catalog;;
            haproxy-status) gtm_haproxy_status "$status_id";;
        esac
        return $?
    fi
    if [[ -n $preview ]]; then
        GTM_DEMO=1
        case $preview in home) gtm_home;; forwards) gtm_header 'Tunnels & Forwards'; gtm_show_records;; *) return 2;; esac
        return
    fi
    if [[ $GTM_DEMO == 0 ]]; then
        ((EUID==0)) || { gtm_error 'Use sudo, or try --demo / --preview home.'; return 1; }
        [[ $(uname -s) == Linux ]] || { gtm_error 'Live operations require Linux with systemd.'; return 1; }
        gtm_need systemctl || return 1
    fi
    if ((legacy)); then gtm_legacy_menu; else gtm_modern_menu; fi
}
