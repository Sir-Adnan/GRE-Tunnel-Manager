# Optional panel lifecycle; the standalone manager stays usable without Go/Node.
gtm_dependencies_menu() {
    local selection component
    local -a components=()
    printf '\n  Install optional engines now. Existing tunnels are not started or changed.\n'
    printf '  [1] All engines\n  [2] HAProxy\n  [3] Realm\n  [4] Kernel forwarding\n  [5] FRP + rathole\n  [0] Back\n'
    gtm_read 'Choose: ' selection || return
    case $selection in
        1) components=(iptables nftables haproxy realm frp rathole);;
        2) components=(haproxy);; 3) components=(realm);;
        4) components=(iptables nftables);; 5) components=(frp rathole);; *) return;;
    esac
    gtm_prepare || return
    for component in "${components[@]}"; do gtm_install_component "$component" || return 1; done
    gtm_pause
}

gtm_panel_install() {
    local tmp result
    gtm_root && gtm_need curl || return 1
    tmp=$(mktemp) || return 1
    if ! curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 15 --max-time 120 'https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/panel-install.sh' -o "$tmp"; then rm -f "$tmp"; return 1; fi
    bash -n "$tmp" && bash "$tmp"; result=$?
    rm -f "$tmp"
    return "$result"
}

gtm_panel_menu() {
    local choice
    while true; do
        gtm_header 'Web Panel'
        printf '\n  Optional browser management. Tunnels run independently of the panel.\n'
        gtm_option 1 'Install / update Web Panel'
        gtm_option 2 'Start Web Panel'
        gtm_option 3 'Stop Web Panel'
        gtm_option 4 'Panel status / address'
        gtm_option 5 'Reset admin password'
        gtm_option 6 'Install tunnel engines'
        gtm_option 0 Back
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_panel_install; gtm_pause;;
            2) systemctl start gre-manager-panel.service; gtm_pause;;
            3) systemctl stop gre-manager-panel.service gre-manager-panel-broker.service; gtm_pause;;
            4) systemctl status gre-manager-panel.service --no-pager; if command -v gtm-panel >/dev/null 2>&1; then gtm-panel address; fi; gtm_pause;;
            5) gtm-panel reset-password && systemctl restart gre-manager-panel.service; gtm_pause;;
            6) gtm_dependencies_menu;; 0) return;;
        esac
    done
}
