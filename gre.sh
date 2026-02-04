#!/bin/bash

# ==================================================
#   GRE MASTER v6.2 - Edit & Force Install
#   Features: Edit Configs, Force Shortcut, Visual UI
# ==================================================

# --- 🎨 THEME & COLORS ---
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
WHITE='\033[1;37m'
GREY='\033[0;90m'
NC='\033[0m'

# --- CONSTANTS ---
SYSCTL_FILE="/etc/sysctl.d/99-gre-tuning.conf"
CACHE_V4="/tmp/gre_v4.cache"
CACHE_V6="/tmp/gre_v6.cache"
SHORTCUT_NAME="igre"
SHORTCUT_PATH="/usr/local/bin/$SHORTCUT_NAME"
# List of APIs for IP detection
API_V4_LIST=("https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip")
API_V6_LIST=("https://api6.ipify.org" "https://ipv6.icanhazip.com" "https://ifconfig.co/ip")

# --- ROOT CHECK ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ Error: This script requires root privileges.${NC}" 
   exit 1
fi

# ==================================================
#   🛠 UTILITIES
# ==================================================

install_deps() {
    local pkgs=""
    # Added 'nano' for the Edit feature
    for tool in curl ip grep awk sed bc nano; do
        if ! command -v $tool &> /dev/null; then pkgs+=" $tool"; fi
    done
    if [[ -n "$pkgs" ]]; then
        echo -e "${GREY}📦 Installing dependencies:${NC} $pkgs"
        apt-get update -qq && apt-get install -y -qq $pkgs > /dev/null
    fi
}

install_shortcut() {
    echo -e "\n${YELLOW}➤ INSTALLING SHORTCUT (FORCE)${NC}"
    print_line
    
    local current_script=$(readlink -f "$0")
    
    # Check if running from a pipe/one-liner (no physical file)
    if [[ "$current_script" == *"/proc/"* ]] || [[ ! -f "$current_script" ]]; then
        echo -e "   ${RED}❌ Error: Cannot install shortcut from a one-liner.${NC}"
        echo -e "   Please save the script to a file first:"
        echo -e "   ${WHITE}nano gre.sh${NC} -> Paste Code -> Save -> ${WHITE}bash gre.sh${NC}"
        echo -ne "\n   Press Enter..."
        read
        return
    fi

    echo -e "   Source: ${WHITE}$current_script${NC}"
    echo -e "   Target: ${WHITE}$SHORTCUT_PATH${NC}"
    
    # Force copy (-f)
    cp -f "$current_script" "$SHORTCUT_PATH"
    chmod +x "$SHORTCUT_PATH"
    
    if [[ -f "$SHORTCUT_PATH" ]]; then
        echo -e "\n   ${GREEN}✔ Shortcut installed/updated successfully!${NC}"
        echo -e "   You can run the tool anytime using: ${BOLD}${CYAN}$SHORTCUT_NAME${NC}"
    else
        echo -e "\n   ${RED}❌ Failed to install shortcut.${NC}"
    fi
    
    echo -ne "\n   Press Enter to continue..."
    read
}

validate_ipv4() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS; IFS='.'; ip_arr=($ip); IFS=$OIFS
        for octet in "${ip_arr[@]}"; do [[ $octet -le 255 ]] || return 1; done
        return 0
    fi
    return 1
}

validate_ipv6() {
    local ip=$1
    [[ -z "$ip" ]] && return 1
    ip -6 route get "$ip" >/dev/null 2>&1
    return $?
}

detect_local_ips() {
    # 1. IPv4
    if [[ -f "$CACHE_V4" ]] && [[ $(find "$CACHE_V4" -mmin -60 2>/dev/null) ]]; then
        LOCAL_V4=$(cat "$CACHE_V4")
    else
        for api in "${API_V4_LIST[@]}"; do
            LOCAL_V4=$(curl -s --max-time 2 -4 "$api")
            if validate_ipv4 "$LOCAL_V4"; then echo "$LOCAL_V4" > "$CACHE_V4"; break; fi
        done
        if ! validate_ipv4 "$LOCAL_V4"; then
            LOCAL_V4=$(hostname -I | tr ' ' '\n' | grep -vE '^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))' | head -n 1)
        fi
    fi

    # 2. IPv6
    if [[ -f "$CACHE_V6" ]] && [[ $(find "$CACHE_V6" -mmin -60 2>/dev/null) ]]; then
        LOCAL_V6=$(cat "$CACHE_V6")
    else
        for api in "${API_V6_LIST[@]}"; do
            LOCAL_V6=$(curl -s --max-time 2 -6 "$api")
            if validate_ipv6 "$LOCAL_V6"; then echo "$LOCAL_V6" > "$CACHE_V6"; break; fi
        done
        if ! validate_ipv6 "$LOCAL_V6"; then
            LOCAL_V6=$(ip -6 -o addr show scope global | grep -v "temporary" | grep -v "deprecated" | awk '{print $4}' | cut -d/ -f1 | head -n 1)
        fi
    fi
}

get_active_tunnels() {
    ip -d link show type gre 2>/dev/null | grep -E ": gre[0-9]+|: gre-out-[0-9]+" | wc -l
}

human_print() {
    local num=${1:-0}
    echo "$num" | awk '{ split( "B KB MB GB TB" , v ); s=1; while( $1>1024 ){ $1/=1024; s++ } printf "%.2f %s", $1, v[s] }'
}

get_total_traffic() {
    grep -E "^\s*(gre[0-9]+|gre-out-[0-9]+):" /proc/net/dev 2>/dev/null | awk '{rx+=$2; tx+=$10} END {print rx+tx}' || echo "0"
}

# ==================================================
#   🎨 UI COMPONENTS
# ==================================================

print_line() {
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
}

draw_header() {
    clear
    echo -e "${CYAN}"
    echo "   ▄▄ • ▄▄▄   ▄▄▄ .    • ▌ ▄ ·.  ▄▄▄· .▄▄ · ▄▄▄▄▄▄▄▄ .▄▄▄  "
    echo "  ▐█ ▀ ▪▀▄ █· ▀▄.▀·    ·██ ▐███▪▐█ ▀█ ▐█ ▀. •██  ▀▄.▀·▀▄ █·"
    echo "  ▄█ ▀█▄▐▀▀▄  ▐▀▀▪▄    ▐█ ▌▐▌▐█·▄█▀▀█ ▄▀▀▀█▄ ▐█.▪▐▀▀▪▄▐▀▀▄ "
    echo "  ▐█▄▪▐█▐█•█▌ ▐█▄▄▌    ██ ██▌▐█▌▐█ ▪▐▌▐█▄▪▐█ ▐█▌·▐█▄▄▌▐█•█▌"
    echo "  ·▀Ss▀▀.▀  ▀  ▀▀▀     ▀▀  █▪▀▀▀ ▀  ▀  ▀▀▀▀  ▀▀▀  ▀▀▀ .▀  ▀"
    echo -e "${NC}"
    echo -e "           ${GREY}VPN TUNNEL MANAGER  |  VERSION 6.2${NC}"
    echo ""
}

draw_dashboard() {
    detect_local_ips
    
    local show_v4="$LOCAL_V4"; [[ -z "$show_v4" ]] && show_v4="${RED}Not Detected${NC}"
    local show_v6="${GREEN}Online${NC}"; [[ -z "$LOCAL_V6" ]] && show_v6="${GREY}Offline${NC}"
    
    local tunnels=$(get_active_tunnels)
    local raw_traffic=$(get_total_traffic)
    local traffic=$(human_print "$raw_traffic")
    local load=$(cat /proc/loadavg | awk '{print $1}')
    
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    printf "${CYAN}║${NC}  🌐 IPv4: %-19b   IPv6: %-22b ${CYAN}║${NC}\n" "${WHITE}$show_v4${NC}" "$show_v6"
    printf "${CYAN}║${NC}  📊 Load: %-19b   🚀 Tunnels: %-19b ${CYAN}║${NC}\n" "${WHITE}$load${NC}" "${YELLOW}$tunnels${NC}"
    printf "${CYAN}║${NC}  📉 Traffic: %-46b ${CYAN}║${NC}\n" "${GREEN}$traffic${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

draw_menu_item() {
    local id=$1
    local icon=$2
    local name=$3
    local desc=$4
    local name_len=${#name}
    local total_dots=32
    local dots=""
    for ((i=0; i<$total_dots-$name_len; i++)); do dots+="."; done
    echo -e "  [${WHITE}$id${NC}] $icon ${CYAN}$name${NC} ${GREY}$dots${NC} $desc"
}

# ==================================================
#   ⚙️ CORE LOGIC
# ==================================================

apply_sysctl() {
    if [[ ! -f "$SYSCTL_FILE" ]]; then
        cat <<EOF > "$SYSCTL_FILE"
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_keepalive_time = 300
net.ipv4.ip_local_port_range = 10000 65000
EOF
        sysctl -p "$SYSCTL_FILE" > /dev/null 2>&1
    fi
}

setup_tunnel() {
    local role=$1
    local role_title=""
    [[ "$role" == "hub" ]] && role_title="HUB SERVER (Foreign)" || role_title="SPOKE SERVER (Iran)"
    
    echo -e "\n${YELLOW}➤ SETUP WIZARD: ${WHITE}$role_title${NC}"
    print_line
    
    detect_local_ips
    
    # STEP 1
    echo -e "\n${BOLD}[1] Remote Configuration${NC}"
    echo -e "${GREY}    Enter the Public IP of the OTHER server.${NC}"
    
    local r_ip=""
    local transport_proto=""
    local local_bind_ip=""
    
    while true; do
        echo -ne "    ${CYAN}Remote IP:${NC} "
        read r_ip
        if validate_ipv4 "$r_ip"; then
            transport_proto="4"; local_bind_ip="$LOCAL_V4"
            echo -e "    ${GREEN}✔ Detected IPv4 Transport${NC}"
            break
        elif validate_ipv6 "$r_ip"; then
            transport_proto="6"; local_bind_ip="$LOCAL_V6"
            if [[ -z "$LOCAL_V6" ]]; then
                echo -e "    ${RED}❌ Local IPv6 missing.${NC}"; return
            fi
            echo -e "    ${GREEN}✔ Detected IPv6 Transport${NC}"
            break
        else
            echo -e "    ${RED}❌ Invalid IP.${NC}"
        fi
    done
    
    # STEP 2
    echo -e "\n${BOLD}[2] Tunnel Identification${NC}"
    echo -e "${GREY}    Enter a unique ID (1-65000).${NC}"
    
    local tid=""
    while true; do
        echo -ne "    ${CYAN}Tunnel ID:${NC} "
        read tid
        [[ "$tid" =~ ^[0-9]+$ ]] && [[ "$tid" -le 65000 ]] && break
        echo -e "    ${RED}❌ Invalid ID.${NC}"
    done
    
    # Pre-Cleanup
    local if_name="gre${tid}"
    [[ $role == "spoke" ]] && if_name="gre-out-${tid}"
    if systemctl is-active --quiet "gre-tun-${tid}.service"; then
        echo -e "    ${YELLOW}⚠ Cleaning existing tunnel ID $tid...${NC}"
        systemctl disable --now "gre-tun-${tid}" "gre-keepalive-${tid}" 2>/dev/null
        rm -f "/etc/systemd/system/gre-tun-${tid}.service" "/etc/systemd/system/gre-keepalive-${tid}.service"
        ip link del "$if_name" 2>/dev/null
        systemctl daemon-reload
    fi
    
    # Calculation
    local octet2=$(( tid / 256 ))
    local octet3=$(( tid % 256 ))
    local v4_int=""; local v6_int=""; local v4_rem=""; local v6_rem=""
    
    if [[ $role == "hub" ]]; then
        v4_int="10.${octet2}.${octet3}.1/30"; v4_rem="10.${octet2}.${octet3}.2"
        v6_int="fd00:${tid}::1/64"; v6_rem="fd00:${tid}::2"
    else
        v4_int="10.${octet2}.${octet3}.2/30"; v4_rem="10.${octet2}.${octet3}.1"
        v6_int="fd00:${tid}::2/64"; v6_rem="fd00:${tid}::1"
    fi
    
    echo -e "\n${PURPLE}╔════ GENERATED INTERNAL ADDRESSES ═══════════════╗${NC}"
    printf "${PURPLE}║${NC} Interface: ${WHITE}%-38s${NC} ${PURPLE}║${NC}\n" "$if_name"
    printf "${PURPLE}║${NC} 👉 ${CYAN}Local v6:${NC} %-30s ${PURPLE}║${NC}\n" "${WHITE}$v6_int${NC}"
    printf "${PURPLE}║${NC} 👉 ${CYAN}Local v4:${NC} %-30s ${PURPLE}║${NC}\n" "${WHITE}$v4_int${NC}"
    echo -e "${PURPLE}╚═════════════════════════════════════════════════╝${NC}"
    
    # STEP 3
    echo -e "\n${BOLD}[3] MTU Optimization${NC}"
    echo -e "    [1] ${WHITE}Auto (1450)${NC} (Recommended)"
    echo -e "    [2] ${WHITE}Custom${NC}"
    local mtu_opt=""; echo -ne "    ${CYAN}Select:${NC} "; read mtu_opt
    local mtu_val=""
    if [[ $mtu_opt == "1" ]]; then mtu_val="1450"
    elif [[ $mtu_opt == "2" ]]; then 
        while true; do echo -ne "    ${CYAN}Value (500-9000):${NC} "; read mtu_val; [[ "$mtu_val" =~ ^[0-9]+$ ]] && [[ "$mtu_val" -ge 500 ]] && break; done
    fi
    
    # Deploy
    echo -e "\n${YELLOW}➤ Deploying...${NC}"
    apply_sysctl
    local s_file="/etc/systemd/system/gre-tun-${tid}.service"
    local w_file="/etc/systemd/system/gre-keepalive-${tid}.service"

    echo "[Unit]
Description=GRE Tunnel $if_name
After=network.target
[Service]
Type=oneshot
RemainAfterExit=yes" > "$s_file"

    if [[ "$transport_proto" == "6" ]]; then
        echo "ExecStart=/sbin/ip -6 tunnel add $if_name mode ip6gre remote $r_ip local $local_bind_ip hoplimit 255" >> "$s_file"
    else
        echo "ExecStart=/sbin/ip tunnel add $if_name mode gre remote $r_ip local $local_bind_ip ttl 255" >> "$s_file"
    fi
    [[ -n "$mtu_val" ]] && echo "ExecStart=/sbin/ip link set dev $if_name mtu $mtu_val" >> "$s_file"
    echo "ExecStart=/sbin/ip link set dev $if_name up
ExecStart=/sbin/ip addr add $v4_int dev $if_name
ExecStart=/sbin/ip -6 addr add $v6_int dev $if_name
ExecStop=/sbin/ip link set dev $if_name down
ExecStop=/sbin/ip tunnel del $if_name
[Install]
WantedBy=multi-user.target" >> "$s_file"

    cat <<EOF > "$w_file"
[Unit]
Description=GRE Watchdog $if_name
After=gre-tun-${tid}.service
Requires=gre-tun-${tid}.service
[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do ping -c 1 -W 2 $v4_rem >/dev/null 2>&1 || ping6 -c 1 -W 2 $v6_rem >/dev/null 2>&1; if [ \$? -ne 0 ]; then logger -t gre-watchdog "Link DOWN: $if_name"; fi; sleep 10; done'
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "gre-tun-${tid}" >/dev/null 2>&1
    systemctl enable --now "gre-keepalive-${tid}" >/dev/null 2>&1
    echo -e "${GREEN}✔ Done! Service: gre-tun-${tid}${NC}"
    echo -ne "\nPress Enter..."
    read
}

remove_tunnel() {
    echo -e "\n${RED}➤ REMOVE TUNNEL${NC}"
    print_line
    mapfile -t services < <(systemctl list-units --type=service --all --no-legend | grep -oE "gre-tun-[0-9]+" | sort -u)
    if [[ ${#services[@]} -eq 0 ]]; then echo -e "${GREY}   No tunnels.${NC}"; sleep 1; return; fi
    
    echo -e "   ${BOLD}ID    Interface    Status${NC}"
    for i in "${!services[@]}"; do
        local tid="${services[$i]##*-}"
        local status=$(systemctl is-active "${services[$i]}")
        local color=$GREEN; [[ "$status" != "active" ]] && color=$RED
        printf "   [${WHITE}%d${NC}]   %-10s   ${color}%s${NC}\n" "$i" "ID: $tid" "$status"
    done
    
    echo -ne "\n   ${RED}Select index:${NC} "; read idx
    if [[ ! "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -ge "${#services[@]}" ]]; then echo -e "   ${RED}Invalid.${NC}"; return; fi
    
    local tid="${services[$idx]##*-}"
    echo -e "   ${YELLOW}Deleting ID $tid...${NC}"
    systemctl disable --now "gre-keepalive-${tid}" "gre-tun-${tid}" >/dev/null 2>&1
    rm -f "/etc/systemd/system/gre-keepalive-${tid}.service" "/etc/systemd/system/gre-tun-${tid}.service"
    ip link del "gre${tid}" 2>/dev/null
    ip link del "gre-out-${tid}" 2>/dev/null
    systemctl daemon-reload
    echo -e "   ${GREEN}✔ Removed.${NC}"
    sleep 1
}

edit_tunnel() {
    echo -e "\n${PURPLE}➤ EDIT CONFIGURATION${NC}"
    print_line
    
    # 1. List Tunnels
    mapfile -t services < <(systemctl list-units --type=service --all --no-legend | grep -oE "gre-tun-[0-9]+" | sort -u)
    
    if [[ ${#services[@]} -eq 0 ]]; then 
        echo -e "${GREY}   No active tunnels found to edit.${NC}"
        sleep 1; return
    fi
    
    echo -e "   ${BOLD}ID    Config File${NC}"
    for i in "${!services[@]}"; do
        local tid="${services[$i]##*-}"
        printf "   [${WHITE}%d${NC}]   %-10s\n" "$i" "gre-tun-${tid}.service"
    done
    
    echo -ne "\n   ${CYAN}Select index to edit:${NC} "; read idx
    if [[ ! "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -ge "${#services[@]}" ]]; then echo -e "   ${RED}Invalid.${NC}"; return; fi
    
    local tid="${services[$idx]##*-}"
    local s_file="/etc/systemd/system/gre-tun-${tid}.service"
    
    if [[ ! -f "$s_file" ]]; then
        echo -e "   ${RED}❌ Error: Config file not found.${NC}"; return
    fi

    echo -e "\n   ${YELLOW}⚠ Opening editor...${NC}"
    echo -e "   ${GREY}Make your changes and save (Ctrl+X, Y, Enter).${NC}"
    sleep 1
    
    # Open Nano
    nano "$s_file"
    
    # Ask to reload
    echo -e "\n   ${CYAN}Applying changes...${NC}"
    systemctl daemon-reload
    systemctl restart "gre-tun-${tid}"
    # Restart watchdog too, just in case remote IP changed
    systemctl restart "gre-keepalive-${tid}"
    
    if systemctl is-active --quiet "gre-tun-${tid}"; then
        echo -e "   ${GREEN}✔ Service updated and restarted successfully!${NC}"
    else
        echo -e "   ${RED}❌ Service failed to restart. Check your config syntax.${NC}"
        systemctl status "gre-tun-${tid}" --no-pager | head -n 10
    fi
    
    echo -ne "\n   Press Enter..."
    read
}

# ==================================================
#   🔄 MAIN LOOP
# ==================================================
install_deps

while true; do
    draw_header
    draw_dashboard
    
    echo -e "${YELLOW} MAIN MENU${NC}"
    draw_menu_item "1" "🚀" "New Hub" "Setup Foreign Server"
    draw_menu_item "2" "📡" "New Spoke" "Setup Iran Server"
    draw_menu_item "3" "🗑️" "Uninstall" "Remove Tunnels"
    draw_menu_item "4" "🔄" "Refresh" "Update Stats"
    draw_menu_item "5" "📲" "Install 'igre'" "Force Install Global Command"
    draw_menu_item "6" "📝" "Edit Config" "Modify Active Tunnels"
    draw_menu_item "0" "❌" "Exit" "Close"
    
    echo ""
    print_line
    echo -ne " ${CYAN}Select Option:${NC} "
    read choice
    
    case $choice in
        1) setup_tunnel "hub" ;;
        2) setup_tunnel "spoke" ;;
        3) remove_tunnel ;;
        4) rm -f "$CACHE_V4" "$CACHE_V6"; sleep 0.5 ;;
        5) install_shortcut ;;
        6) edit_tunnel ;;
        0) clear; exit 0 ;;
        *) echo "Invalid option." ;;
    esac
done
