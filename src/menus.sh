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
        gtm_option 0 Back
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_new_forward iptables;; 2) gtm_new_forward nftables;;
            3) gtm_show_records; gtm_pause;; 4) gtm_edit_forward;;
            5) gtm_mutate_selected delete;; 6) gtm_toggle_menu;;
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

gtm_engine_home() {
    local engine=$1 title=$2 GTM_ENGINE_FILTER=$1
    gtm_header "$title Manager"
    gtm_records || return 1
    printf '  Saved tunnels: %s\n\n' "${#GTM_RECORDS[@]}"
    gtm_option 1 'Add Tunnel'
    gtm_option 2 'Load Balancing'
    gtm_option 3 'Show Tunnels'
    gtm_option 4 'Edit Tunnel'
    gtm_option 5 'Delete Tunnel'
    gtm_option 6 'Start / Stop'
    gtm_option 7 'Status & Logs'
    [[ $engine != haproxy ]] || gtm_option 8 'Advanced Settings'
    gtm_option 0 Back
}

gtm_engine_menu() {
    local engine=$1 title=$2 choice GTM_ENGINE_FILTER=$1
    while true; do
        gtm_engine_home "$engine" "$title" || return 1
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_new_forward "$engine";; 2) gtm_new_forward "$engine" '' balance;;
            3) gtm_show_records; gtm_pause;; 4) gtm_edit_forward;;
            5) gtm_mutate_selected delete;; 6) gtm_toggle_menu;;
            7) gtm_engine_service "$engine" "$title";; 8) [[ $engine != haproxy ]] || gtm_haproxy_settings;;
            0) return;; *) gtm_error 'Choose one of the shown options.';;
        esac
    done
}

gtm_engine_service() {
    local engine=$1 title=$2 choice id row selected result
    gtm_header "$title / Status & Logs"
    gtm_show_records || return 1
    ((${#GTM_RECORDS[@]})) || return 0
    gtm_read 'Tunnel number (0 = back)' choice || return 1
    gtm_uint "$choice" 1 "${#GTM_RECORDS[@]}" || return 0
    selected=${GTM_RECORDS[$((10#$choice-1))]}; id=${selected%%$'\t'*}
    gtm_choose 'Service' status Status status 'Recent logs' logs Restart restart || return 0
    choice=$GTM_REPLY
    if [[ ${GTM_DEMO:-0} == 1 ]]; then printf 'Demo / no service commands run.\n'; gtm_pause; return 0; fi
    case $choice in
        status) systemctl status "gtm-$id.service" --no-pager;;
        logs) journalctl -u "gtm-$id.service" -n 60 --no-pager;;
        restart)
            gtm_confirm && gtm_prepare && gtm_lock || return 1
            if ! gtm_load_records; then gtm_unlock; return 1; fi
            row=''
            for selected in "${GTM_RECORDS[@]}"; do [[ ${selected%%$'\t'*} != "$id" ]] || row=$selected; done
            if ! gtm_record_validate "$row" || [[ $R_ENGINE != "$engine" || $R_ENABLED != 1 ]]; then
                gtm_unlock; gtm_error 'Tunnel changed or is stopped. Reopen the service menu.'; return 1
            fi
            if gtm_preflight && systemctl restart "gtm-$id.service"; then
                if [[ $engine == haproxy ]]; then gtm_haproxy_wait "$id" 0; result=$?
                else sleep 1; systemctl is-active --quiet "gtm-$id.service"; result=$?; fi
            else result=1; fi
            gtm_unlock
            ((result==0)) || { gtm_error 'Restart failed. Check the tunnel logs.'; return 1; };;
    esac
    gtm_pause
}

# Local source address the kernel would use toward remote; sends no packet.
gtm_route_source() {
    local family=4 line
    [[ $1 != *:* ]] || family=6
    line=$(ip -o -"$family" route get "$1" 2>/dev/null) || return 1
    [[ $line =~ \ src\ ([0-9a-fA-F:.]+) ]] && printf '%s' "${BASH_REMATCH[1]}"
}

# The terminal and the panel create GRE through the same engine (links.sh).
gtm_gre_create() {
    local role=$1 remote bind tid mtu maximum=1472 result
    gtm_header "GRE Tunnel / ${role^} server"
    gtm_help links
    gtm_ask_ip 'Public IP of the other server' '' || return
    remote=$GTM_REPLY
    [[ $remote != *:* ]] || maximum=1452
    bind=$(gtm_route_source "$remote") || bind=''
    gtm_ask_ip 'Local IP for this tunnel' "$bind" || return
    bind=$GTM_REPLY
    while true; do
        gtm_default 'Tunnel ID (1-250, the same on both servers)' tid '' || return
        gtm_uint "$tid" 1 250 && break
        gtm_error 'Use a number from 1 to 250.'
    done
    while true; do
        gtm_default "MTU (1280-$maximum)" mtu 1430 || return
        gtm_uint "$mtu" 1280 "$maximum" && break
        gtm_error "Use a value from 1280 to $maximum."
    done
    printf '\n  GRE %d  %s -> %s  MTU %d  (%s side)\n' "$((10#$tid))" "$bind" "$remote" "$((10#$mtu))" "$role"
    if [[ ${GTM_DEMO:-0} == 1 ]]; then printf '  Demo: nothing was created.\n'; gtm_pause; return 0; fi
    gtm_confirm && gtm_prepare && gtm_lock || return
    gtm_link_create "$tid" "$role" "$remote" "$bind" "$mtu"; result=$?
    gtm_unlock; gtm_pause
    return "$result"
}

# Prints "id interface remote mtu state" for each managed GRE unit.
gtm_gre_rows() {
    local unit id iface remote mtu state
    if [[ ${GTM_DEMO:-0} == 1 ]]; then printf '10 gre-out-10 203.0.113.20 1430 active\n'; return; fi
    for unit in "$GTM_SERVICE_DIR"/gre-tun-*.service; do
        [[ -f $unit ]] || continue
        id=${unit##*/gre-tun-}; id=${id%.service}
        gtm_uint "$id" 1 250 || continue
        iface=$(awk '/ tunnel add / {for (i=1;i<=NF;i++) if ($i=="add") {print $(i+1); exit}}' "$unit")
        remote=$(awk '/ tunnel add / {for (i=1;i<=NF;i++) if ($i=="remote") {print $(i+1); exit}}' "$unit")
        mtu=$(awk '/ mtu / {for (i=1;i<=NF;i++) if ($i=="mtu") {print $(i+1); exit}}' "$unit")
        state=$(systemctl is-active "gre-tun-$id" 2>/dev/null) || true
        printf '%s %s %s %s %s\n' "$id" "${iface:--}" "${remote:--}" "${mtu:--}" "${state:-unknown}"
    done
}

gtm_gre_show() {
    local id iface remote mtu state count=0
    while read -r id iface remote mtu state; do
        ((count+=1))
        printf '  %bGRE %-4s%b %-12s peer %-40s MTU %-5s %s\n' "$BOLD" "$id" "$GTM_RESET" "$iface" "$remote" "$mtu" "$state"
    done < <(gtm_gre_rows)
    ((count)) || printf '\n  No GRE tunnels yet.\n'
    return 0
}

gtm_gre_delete() {
    local tid result
    gtm_header 'GRE Tunnel / Delete'
    gtm_gre_show
    gtm_default 'Tunnel ID to delete (0 cancels)' tid 0 || return
    gtm_uint "$tid" 1 250 || return
    printf '\n  GRE %d stops and its unit is removed. Forwards that still use it block the delete.\n' "$((10#$tid))"
    if [[ ${GTM_DEMO:-0} == 1 ]]; then printf '  Demo: nothing was deleted.\n'; gtm_pause; return 0; fi
    gtm_confirm && gtm_prepare && gtm_lock || return
    gtm_link_delete "$tid"; result=$?
    gtm_unlock
    ((result)) || printf 'GRE %d removed.\n' "$((10#$tid))"
    gtm_pause
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
        gtm_option 0 Back
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_gre_create kharej;; 2) gtm_gre_create iran;;
            3) gtm_header 'GRE Tunnel / Show'; gtm_gre_show; gtm_pause;;
            4) gtm_gre_delete;;
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

gtm_home() {
    gtm_header 'Main Menu'
    printf '\n'
    gtm_option 1 'GRE Tunnel' 'Create / show / delete'
    gtm_option 2 'Port Forwarding' 'iptables / nftables'
    gtm_option 3 'HAProxy Tunnel' 'TCP tunnel'
    gtm_option 4 'Realm Tunnel' 'TCP / UDP tunnel'
    gtm_option 5 'Reverse Tunnel' 'FRP / rathole'
    gtm_option 6 'Load Balancing' 'Use more than one server'
    gtm_option 7 Tools 'Status / backup / help'
    gtm_option 8 'Web Panel' 'Install / open / manage'
    gtm_option 0 Exit
    gtm_panel_end
}

gtm_tools_menu() {
    local choice
    while true; do
        gtm_header Tools
        gtm_option 1 'Server Status'
        gtm_option 2 'Restore Backup'
        gtm_option 3 'Install / Update igre'
        gtm_option 4 'Server optimization' 'Opt-in, reversible'
        gtm_option 5 'Retire old installation' 'v13.x rules / Simple GRE / old tuning files'
        gtm_option 6 Help
        gtm_option 7 'Show Configuration'
        gtm_option 8 'Refresh Server Info'
        gtm_option 9 'Install Tunnel Engines'
        gtm_option 0 Back
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_diagnostics;; 2) gtm_restore_menu;;
            3|5)
                gtm_prepare && gtm_lock || return
                case $choice in 3) gtm_update_shortcut;; 5) gtm_legacy_cleanup_menu;; esac
                gtm_unlock;;
            4) gtm_optimize_menu;;
            6) gtm_catalog; gtm_pause;; 0) return;;
            7) if [[ ${GTM_DEMO:-0} == 1 ]]; then printf 'Use --plan --state-file FILE to inspect a saved configuration.\n'; else gtm_plan; fi; gtm_pause;;
            8) GTM_SERVER_INFO_READY=0;;
            9) gtm_dependencies_menu;;
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
    case $choice in 1) gtm_new_forward iptables '' balance;; 2) gtm_new_forward nftables '' balance;; 3) gtm_new_forward haproxy '' balance;; 4) gtm_new_forward realm '' balance;; 5) gtm_frp_menu;; esac
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
            8) gtm_panel_menu;;
            *) gtm_error 'Choose one of the shown options.';;
        esac
    done
}

GTM_SHORTCUT_PATH=/usr/local/bin/igre
GTM_REPO_URL=https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/gre.sh

gtm_update_shortcut() {
    local tmp
    tmp=$(mktemp "${GTM_SHORTCUT_PATH}.XXXXXX") || return 1
    curl --proto '=https' --tlsv1.2 -fL --connect-timeout 15 --max-time 120 "$GTM_REPO_URL" -o "$tmp" && bash -n "$tmp" && chmod 755 "$tmp" && mv "$tmp" "$GTM_SHORTCUT_PATH" || { rm -f "$tmp"; return 1; }
    printf 'Shortcut updated. Run igre again to load the new version.\n'
}

gtm_main() {
    local preview='' action='' state_file='' status_id=''
    GTM_DEMO=0
    gtm_paths
    if [[ ${1:-} == --api ]]; then shift; gtm_api "$@"; return $?; fi
    if [[ ${1:-} == --panel ]]; then shift; (($#==0)) && gtm_root && gtm_panel_menu; return $?; fi
    while (( $# )); do
        case $1 in
            --help|-h) printf 'GRE Tunnel Manager %s\nUsage: bash gre.sh [--demo] [--preview home|forwards|haproxy|realm]\nRead only:\n  --validate | --plan [--state-file PATH]\n  --doctor | --catalog | --haproxy-status F000001\n' "$GTM_VERSION"; return;;
            --version) printf 'v%s\n' "$GTM_VERSION"; return;;
            --demo) GTM_DEMO=1;;
            --validate|--plan|--doctor|--catalog) [[ -z $action ]] || { gtm_error 'Choose one inspection action.'; return 2; }; action=${1#--};;
            --haproxy-status) [[ -z $action && $# -ge 2 ]] && gtm_id "$2" || return 2; action=haproxy-status; status_id=$2; shift;;
            --state-file) (( $#>=2 )) && [[ -n $2 ]] || return 2; state_file=$2; shift;;
            --preview) (( $#>=2 )) || return 2; preview=$2; shift;;
            *) gtm_error "Unknown argument: $1"; return 2;;
        esac
        shift
    done
    gtm_palette
    if [[ -n $state_file && $action != validate && $action != plan ]]; then gtm_error '--state-file requires --validate or --plan.'; return 2; fi
    if [[ -n $action ]]; then
        [[ -z $preview ]] || { gtm_error 'Inspection actions cannot be combined with menus or UI previews.'; return 2; }
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
        case $preview in home) gtm_home;; forwards) gtm_header 'Tunnels & Forwards'; gtm_show_records;; haproxy) gtm_engine_home haproxy HAProxy;; realm) gtm_engine_home realm Realm;; *) return 2;; esac
        return
    fi
    if [[ $GTM_DEMO == 0 ]]; then
        ((EUID==0)) || { gtm_error 'Use sudo, or try --demo / --preview home.'; return 1; }
        [[ $(uname -s) == Linux ]] || { gtm_error 'Live operations require Linux with systemd.'; return 1; }
        gtm_need systemctl || return 1
    fi
    gtm_modern_menu
}
