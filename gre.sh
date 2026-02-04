#!/bin/bash

# ==================================================
#   GRE MASTER v9.0 - NAT Fix & Auto Firewall
#   Fixed: Connection Timeout, NAT Binding, Firewall
# ==================================================

# --- 🎨 THEME ---
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
SHORTCUT_NAME="igre"
SHORTCUT_PATH="/usr/local/bin/$SHORTCUT_NAME"

# --- ROOT CHECK ---
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ Error: Run as root (sudo).${NC}" 
    exit 1
fi

# ==================================================
#   🛠 UTILITIES
# ==================================================

install_deps() {
    local pkgs=""
    for tool in curl ip grep awk sed bc nano iptables; do
        if ! command -v $tool &> /dev/null; then pkgs+=" $tool"; fi
    done
    if [[ -n "$pkgs" ]]; then
        clear
        echo -e "${GREY}📦 Installing tools...${NC}"
        apt-get update -qq && apt-get install -y -qq $pkgs > /dev/null
    fi
}

install_shortcut() {
    echo -e "\n${YELLOW}➤ INSTALL SHORTCUT${NC}"
    local current_script=$(readlink -f "$0")
    if [[ "$current_script" == *"/proc/"* ]] || [[ ! -f "$current_script" ]]; then
        echo -e "   ${RED}❌ Save file first.${NC}"
        read -p "Press Enter..."
        return
    fi
    cp -f "$current_script" "$SHORTCUT_PATH"
    chmod +x "$SHORTCUT_PATH"
    echo -e "   ${GREEN}✔ Installed!${NC} Run: ${BOLD}${CYAN}$SHORTCUT_NAME${NC}"
    read -p "   Press Enter..."
}

# --- SMART IP DETECTION (THE FIX) ---
get_bind_ip() {
    local remote_ip=$1
    # Find which local IP is used to reach the remote IP
    local bind_ip=$(ip route get "$remote_ip" | grep -oP 'src \K\S+')
    echo "$bind_ip"
}

get_public_ip() {
    curl -s --max-time 3 https://api.ipify.org || curl -s --max-time 3 https://ipv4.icanhazip.com
}

configure_firewall() {
    echo -e "${GREY}   🛡️  Configuring Firewall (Allow GRE)...${NC}"
    # UFW
    if command -v ufw &> /dev/null; then
        ufw allow proto gre >/dev/null 2>&1
    fi
    # IPTables
    iptables -C INPUT -p gre -j ACCEPT 2>/dev/null || iptables -A INPUT -p gre -j ACCEPT
}

# ==================================================
#   🎨 UI
# ==================================================

draw_logo() {
    clear
    echo -e "${CYAN}"
    echo "   ▄▄ • ▄▄▄   ▄▄▄ .   • ▌ ▄ ·. ▄▄▄· .▄▄ · "
    echo "   ▐█ ▀ ▪▀▄ █·▀▄.▀·   ·██ ▐███▪▐█ ▀█ ▐█ ▀. "
    echo "   ▄█ ▀█▄▐▀▀▄ ▐▀▀▪▄   ▐█ ▌▐▌▐█·▄█▀▀█ ▄▀▀▀█▄"
    echo "   ▐█▄▪▐█▐█•█▌▐█▄▄▌   ██ ██▌▐█▌▐█ ▪▐▌▐█▄▪▐█"
    echo "   ·▀Ss▀▀.▀  ▀ ▀▀▀    ▀▀  █▪▀▀▀ ▀  ▀  ▀▀▀▀ "
    echo -e "${NC}"
    echo -e "         ${GREY}VPN TUNNEL MANAGER  |  v9.0 (NAT FIX)${NC}"
    echo ""
}

print_guide_box() {
    echo -e "${PURPLE}┌──[ 💡 HELP: $1 ]───────────────────────────────────────┐${NC}"
    echo -e "${PURPLE}│${NC} $2"
    echo -e "${PURPLE}└────────────────────────────────────────────────────────────┘${NC}"
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
EOF
        sysctl -p "$SYSCTL_FILE" > /dev/null 2>&1
    fi
}

setup_tunnel() {
    local role=$1
    local remote_desc=""
    [[ "$role" == "kharej" ]] && remote_desc="Enter public IP of **IRAN**." || remote_desc="Enter public IP of **KHAREJ**."
    
    echo -e "\n${YELLOW}➤ SETUP: ${role^^}${NC}"
    print_guide_box "Remote IP" "$remote_desc"
    
    # 1. Get Remote IP
    local r_ip=""
    while true; do
        echo -ne "   ${WHITE}➤ Remote IP:${NC} "
        read r_ip
        [[ "$r_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && break
        echo -e "     ${RED}❌ Please enter a valid IPv4.${NC}"
    done
    
    # 2. Get ID
    echo ""
    print_guide_box "Tunnel ID" "Enter a number (1-250). MUST match the other server!"
    local tid=""
    while true; do
        echo -ne "   ${WHITE}➤ Tunnel ID:${NC} "
        read tid
        [[ "$tid" =~ ^[0-9]+$ ]] && [[ "$tid" -le 65000 ]] && break
        echo -e "     ${RED}❌ Invalid number.${NC}"
    done
    
    # 3. Detect Correct Local IP (NAT Fix)
    local local_bind_ip=$(get_bind_ip "$r_ip")
    echo -e "     ${GREY}ℹ️  System will bind to local IP: ${WHITE}$local_bind_ip${NC}"
    
    # Cleanup
    local if_name="gre${tid}"
    [[ $role == "iran" ]] && if_name="gre-out-${tid}"
    
    systemctl stop "gre-tun-${tid}" "gre-keepalive-${tid}" 2>/dev/null
    rm -f "/etc/systemd/system/gre-tun-${tid}.service" "/etc/systemd/system/gre-keepalive-${tid}.service"
    ip link del "$if_name" 2>/dev/null
    systemctl daemon-reload

    # Calc Internal IPs
    local octet2=$(( tid / 256 ))
    local octet3=$(( tid % 256 ))
    local v4_int=""; local v6_int=""; local v4_rem=""; local v6_rem=""
    
    if [[ $role == "kharej" ]]; then
        v4_int="10.${octet2}.${octet3}.1/30"; v4_rem="10.${octet2}.${octet3}.2"
        v6_int="fd00:${tid}::1/64"; v6_rem="fd00:${tid}::2"
    else
        v4_int="10.${octet2}.${octet3}.2/30"; v4_rem="10.${octet2}.${octet3}.1"
        v6_int="fd00:${tid}::2/64"; v6_rem="fd00:${tid}::1"
    fi
    
    # Deploy
    echo -e "\n${YELLOW}➤ Deploying...${NC}"
    apply_sysctl
    configure_firewall # Allow GRE
    
    local s_file="/etc/systemd/system/gre-tun-${tid}.service"
    local w_file="/etc/systemd/system/gre-keepalive-${tid}.service"

    echo "[Unit]
Description=GRE Tunnel $if_name
After=network.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip tunnel add $if_name mode gre remote $r_ip local $local_bind_ip ttl 255
ExecStart=/sbin/ip link set dev $if_name mtu 1430
ExecStart=/sbin/ip link set dev $if_name up
ExecStart=/sbin/ip addr add $v4_int dev $if_name
ExecStart=/sbin/ip -6 addr add $v6_int dev $if_name
ExecStop=/sbin/ip link set dev $if_name down
ExecStop=/sbin/ip tunnel del $if_name
[Install]
WantedBy=multi-user.target" > "$s_file"

    cat <<EOF > "$w_file"
[Unit]
Description=Watchdog $if_name
After=gre-tun-${tid}.service
[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do ping -c 1 -W 2 $v4_rem >/dev/null 2>&1; sleep 10; done'
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "gre-tun-${tid}" >/dev/null 2>&1
    systemctl enable --now "gre-keepalive-${tid}" >/dev/null 2>&1
    
    # Result
    clear
    echo -e "${GREEN}"
    echo "   ✅  TUNNEL UPDATED & FIREWALL FIXED"
    echo -e "${NC}"
    printf "   %-15s : ${WHITE}%s${NC}\n" "Tunnel ID" "$tid"
    printf "   %-15s : ${GREEN}%s${NC}\n" "Internal IPv4" "$v4_int"
    echo ""
    echo -e "   ${GREY}Wait 5 seconds then try pinging from the other side.${NC}"
    read -p "   Press Enter..."
}

remove_tunnel() {
    echo -e "\n${RED}➤ DELETE${NC}"
    local files=(/etc/systemd/system/gre-tun-*.service)
    if [[ ! -e "${files[0]}" ]]; then echo "   No tunnels found."; sleep 1; return; fi
    
    echo -e "   ${BOLD}ID    Config${NC}"
    local count=0; local available_ids=()
    for file in "${files[@]}"; do
        if [[ $file =~ gre-tun-([0-9]+)\.service ]]; then
            local id="${BASH_REMATCH[1]}"
            echo "   [$count] Tunnel $id"
            available_ids+=("$id")
            ((count++))
        fi
    done
    
    echo -ne "\n   Select: "; read idx
    if [[ -z "${available_ids[$idx]}" ]]; then return; fi
    local tid="${available_ids[$idx]}"
    
    systemctl stop "gre-keepalive-${tid}" "gre-tun-${tid}" 2>/dev/null
    systemctl disable "gre-keepalive-${tid}" "gre-tun-${tid}" 2>/dev/null
    rm -f "/etc/systemd/system/gre-keepalive-${tid}.service" "/etc/systemd/system/gre-tun-${tid}.service"
    ip link del "gre${tid}" 2>/dev/null
    ip link del "gre-out-${tid}" 2>/dev/null
    systemctl daemon-reload
    echo -e "   ${GREEN}✔ Deleted.${NC}"
    sleep 1
}

test_tunnel() {
    echo -e "\n${BLUE}➤ DEBUG MODE${NC}"
    local files=(/etc/systemd/system/gre-tun-*.service)
    if [[ ! -e "${files[0]}" ]]; then echo "   No tunnels to test."; sleep 1; return; fi

    # Just verify firewall
    echo -e "   🛡️  Checking Firewall rules..."
    if iptables -L INPUT -n | grep -q "47"; then
        echo -e "      ${GREEN}✔ IPTables: GRE (Proto 47) is ALLOWED${NC}"
    else
        echo -e "      ${RED}❌ IPTables: GRE rule missing. Attempting to fix...${NC}"
        configure_firewall
    fi
    echo ""
    read -p "   Press Enter to return..."
}

# ==================================================
#   🔄 MAIN
# ==================================================
install_deps

while true; do
    draw_logo
    local my_pub=$(get_public_ip)
    echo -e "   My Public IP: ${WHITE}$my_pub${NC}"
    echo -e "${GREY}──────────────────────────────────────────────${NC}"
    
    echo -e " ${BOLD}[1] ${CYAN}Kharej Server${NC}"
    echo -e " ${BOLD}[2] ${CYAN}Iran Server${NC}"
    echo -e " ${BOLD}[3] ${RED}Delete Tunnel${NC}"
    echo -e " ${BOLD}[4] ${BLUE}Debug / Test Firewall${NC}"
    echo -e " ${BOLD}[5] ${GREEN}Install Shortcut${NC}"
    echo -e " ${BOLD}[0] ${WHITE}Exit${NC}"
    
    echo -ne "\n ${WHITE}Select:${NC} "
    read choice
    
    case $choice in
        1) setup_tunnel "kharej" ;;
        2) setup_tunnel "iran" ;;
        3) remove_tunnel ;;
        4) test_tunnel ;;
        5) install_shortcut ;;
        0) clear; exit 0 ;;
        *) echo "Invalid." ;;
    esac
done
