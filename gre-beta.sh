#!/bin/bash

# ==================================================
#   GRE MASTER v12.5 - The Perfect Fusion
#   Visuals: v8.0 Style | Logic: v12.0 Fixes
#   Update: Fixed Internal IPv6 Display in Summary
# ==================================================

# --- 🎨 THEME & COLORS ---
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
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
API_V4_LIST=("https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip")
API_V6_LIST=("https://api6.ipify.org" "https://ipv6.icanhazip.com" "https://ifconfig.co/ip")

# --- ROOT CHECK ---
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ Error: This script requires root privileges (sudo).${NC}" 
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
        echo -e "${GREY}📦 Installing dependencies:${NC} $pkgs"
        apt-get update -qq && apt-get install -y -qq $pkgs > /dev/null
    fi
}

install_shortcut() {
    echo -e "\n${YELLOW}➤ INSTALLING SHORTCUT${NC}"
    local current_script=$(readlink -f "$0")
    if [[ "$current_script" == *"/proc/"* ]] || [[ ! -f "$current_script" ]]; then
        echo -e "   ${RED}❌ Error: Save the script to a file first.${NC}"
        read -p "Press Enter..."
        return
    fi
    cp -f "$current_script" "$SHORTCUT_PATH"
    chmod +x "$SHORTCUT_PATH"
    echo -e "   ${GREEN}✔ Installed!${NC} You can now run '${BOLD}${CYAN}$SHORTCUT_NAME${NC}' anywhere."
    read -p "   Press Enter to continue..."
}

# --- LOGIC FIXES ---
get_bind_ip() {
    local remote_ip=$1
    local bind_ip=$(ip route get "$remote_ip" | grep -oP 'src \K\S+')
    echo "$bind_ip"
}

fix_firewall() {
    if command -v ufw &> /dev/null; then
        ufw allow proto gre >/dev/null 2>&1
    fi
    iptables -C INPUT -p gre -j ACCEPT 2>/dev/null || iptables -A INPUT -p gre -j ACCEPT
}

validate_ipv4() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
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

# ==================================================
#   🎨 UI COMPONENTS
# ==================================================

draw_logo() {
    clear
    echo -e "${CYAN}"
    echo "  ▄▄ • ▄▄▄    ▄▄▄ .    • ▌ ▄ ·.  ▄▄▄· .▄▄ · "
    echo "  ▐█ ▀ ▪▀▄ █· ▀▄.▀·    ·██ ▐███▪▐█ ▀█ ▐█ ▀. "
    echo "  ▄█ ▀█▄▐▀▀▄  ▐▀▀▪▄    ▐█ ▌▐▌▐█·▄█▀▀█ ▄▀▀▀█▄"
    echo "  ▐█▄▪▐█▐█•█▌ ▐█▄▄▌    ██ ██▌▐█▌▐█ ▪▐▌▐█▄▪▐█"
    echo "  ·▀Ss▀▀.▀  ▀  ▀▀▀     ▀▀  █▪▀▀▀ ▀  ▀  ▀▀▀▀ "
    echo -e "${NC}"
    echo -e "         ${GREY}VPN TUNNEL MANAGER  |  v12.5${NC}"
    echo ""
}

draw_dashboard() {
    detect_local_ips
    local show_v4="$LOCAL_V4"; [[ -z "$show_v4" ]] && show_v4="${RED}Not Detected${NC}"
    local show_v6="${GREEN}Online${NC}"; [[ -z "$LOCAL_V6" ]] && show_v6="${GREY}Offline${NC}"
    local tunnels=$(get_active_tunnels)
    local load=$(cat /proc/loadavg | awk '{print $1}')

    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    printf "${CYAN}║${NC}  🌐 IPv4: %-19b   IPv6: %-22b ${CYAN}║${NC}\n" "${WHITE}$show_v4${NC}" "$show_v6"
    printf "${CYAN}║${NC}  📊 Load: %-19b   🚀 Tunnels: %-19b ${CYAN}║${NC}\n" "${WHITE}$load${NC}" "${YELLOW}$tunnels${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_guide_box() {
    local title="$1"
    local text="$2"
    echo -e "${PURPLE}┌──[ 💡 HELP: $title ]───────────────────────────────────────┐${NC}"
    echo -e "${PURPLE}│${NC} $text"
    echo -e "${PURPLE}└────────────────────────────────────────────────────────────┘${NC}"
}

# ==================================================
#   ⚙️ CORE LOGIC (Standard GRE)
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
    echo -e "\n${YELLOW}➤ SETUP WIZARD: ${role^^}${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    
    local remote_desc=""
    [[ "$role" == "kharej" ]] && remote_desc="Enter the Public IP of your ${BOLD}IRAN${NC} server." || remote_desc="Enter the Public IP of your ${BOLD}KHAREJ${NC} server."
    print_guide_box "Remote Connection" "$remote_desc"
    
    local r_ip=""; local transport_proto=""
    while true; do
        echo -ne "   ${WHITE}➤ Remote IP:${NC} "
        read r_ip
        if validate_ipv4 "$r_ip"; then transport_proto="4"; echo -e "     ${GREEN}✔ IPv4 Detected.${NC}"; break
        elif validate_ipv6 "$r_ip"; then transport_proto="6"; 
            [[ -z "$LOCAL_V6" ]] && echo -e "     ${RED}❌ Error: You don't have IPv6.${NC}" && return
            echo -e "     ${GREEN}✔ IPv6 Detected.${NC}"; break
        else echo -e "     ${RED}❌ Invalid IP format.${NC}"; fi
    done
    
    echo ""
    print_guide_box "Tunnel ID" "Pick a number (1-250). ${BOLD}MUST be the same${NC} on both servers!"
    local tid=""
    while true; do
        echo -ne "   ${WHITE}➤ Tunnel ID:${NC} "; read tid
        [[ "$tid" =~ ^[0-9]+$ ]] && [[ "$tid" -le 65000 ]] && break
        echo -e "     ${RED}❌ Invalid number.${NC}"
    done

    local local_bind_ip=""; 
    [[ "$transport_proto" == "4" ]] && local_bind_ip=$(get_bind_ip "$r_ip") || local_bind_ip="$LOCAL_V6"
    
    local if_name="gre${tid}"
    [[ $role == "iran" ]] && if_name="gre-out-${tid}"
    
    if systemctl list-units --full -all | grep -q "gre-tun-${tid}.service"; then
        echo -e "     ${YELLOW}⚠ Overwriting existing tunnel $tid...${NC}"
        systemctl stop "gre-tun-${tid}" "gre-keepalive-${tid}" 2>/dev/null
        rm -f "/etc/systemd/system/gre-tun-${tid}.service" "/etc/systemd/system/gre-keepalive-${tid}.service"
        ip link del "$if_name" 2>/dev/null; systemctl daemon-reload
    fi

    local octet2=$(( tid / 256 )); local octet3=$(( tid % 256 ))
    local v4_int=""; local v6_int=""; local v4_rem=""; local v6_rem=""
    
    if [[ $role == "kharej" ]]; then
        v4_int="10.${octet2}.${octet3}.1/30"; v4_rem="10.${octet2}.${octet3}.2"
        v6_int="fd00:${tid}::1/64"; v6_rem="fd00:${tid}::2"
    else
        v4_int="10.${octet2}.${octet3}.2/30"; v4_rem="10.${octet2}.${octet3}.1"
        v6_int="fd00:${tid}::2/64"; v6_rem="fd00:${tid}::1"
    fi
    
    echo -e "\n${YELLOW}➤ Deploying configuration...${NC}"
    apply_sysctl; fix_firewall
    
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
    
    echo "ExecStart=/sbin/ip link set dev $if_name mtu 1430
ExecStart=/sbin/ip link set dev $if_name up
ExecStart=/sbin/ip addr add $v4_int dev $if_name
ExecStart=/sbin/ip -6 addr add $v6_int dev $if_name
ExecStop=/sbin/ip link set dev $if_name down
ExecStop=/sbin/ip tunnel del $if_name
[Install]
WantedBy=multi-user.target" >> "$s_file"

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
    
    clear
    echo -e "${GREEN} "
    echo "   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄"
    echo "   █                                               █"
    echo "   █           ✅  TUNNEL ESTABLISHED              █"
    echo "   █                                               █"
    echo "   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀"
    echo -e "${NC}"
    printf "   %-15s : ${WHITE}%s${NC}\n" "Tunnel ID" "$tid"
    printf "   %-15s : ${GREEN}%s${NC}\n" "Internal IPv4" "$v4_int"
    printf "   %-15s : ${GREEN}%s${NC}\n" "Internal IPv6" "$v6_int"
    print_guide_box "Next Step" "Copy the ${GREEN}Internal IPv4${NC} above and use it in your Panel (3x-ui/Hiddify) as the destination."
    echo -ne "\n   Press Enter to return to menu..."
    read
}

remove_tunnel() {
    echo -e "\n${RED}➤ DELETE MENU${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    local files=(/etc/systemd/system/gre-tun-*.service)
    if [[ ! -e "${files[0]}" ]]; then echo -e "   ${GREY}No active tunnels found.${NC}"; read -p "   Press Enter..."; return; fi
    
    echo -e "   ${BOLD}ID    Status     Config File${NC}"
    local count=0; local available_ids=()
    for file in "${files[@]}"; do
        if [[ $file =~ gre-tun-([0-9]+)\.service ]]; then
            local id="${BASH_REMATCH[1]}"
            local status=$(systemctl is-active "gre-tun-${id}")
            local color=$GREEN; [[ "$status" != "active" ]] && color=$RED
            printf "   [${WHITE}%d${NC}]   ${color}%-9s${NC}  gre-tun-${id}\n" "$count" "$status"
            available_ids+=("$id"); ((count++))
        fi
    done
    echo -ne "\n   ${RED}Select index to delete:${NC} "; read idx
    if [[ -z "${available_ids[$idx]}" ]]; then echo -e "   ${RED}Invalid selection.${NC}"; sleep 1; return; fi
    local tid="${available_ids[$idx]}"
    echo -e "\n   ${YELLOW}Deleting Tunnel $tid...${NC}"
    systemctl stop "gre-keepalive-${tid}" "gre-tun-${tid}" 2>/dev/null
    systemctl disable "gre-keepalive-${tid}" "gre-tun-${tid}" 2>/dev/null
    rm -f "/etc/systemd/system/gre-keepalive-${tid}.service" "/etc/systemd/system/gre-tun-${tid}.service"
    ip link del "gre${tid}" 2>/dev/null; ip link del "gre-out-${tid}" 2>/dev/null
    systemctl daemon-reload; systemctl reset-failed
    echo -e "   ${GREEN}✔ Deleted successfully.${NC}"; read -p "   Press Enter..."
}

edit_tunnel() {
    local files=(/etc/systemd/system/gre-tun-*.service)
    if [[ ! -e "${files[0]}" ]]; then echo -e "   ${GREY}No tunnels.${NC}"; sleep 1; return; fi
    echo -e "\n${PURPLE}➤ EDITOR MODE${NC}"
    local count=0; local available_ids=()
    for file in "${files[@]}"; do
        if [[ $file =~ gre-tun-([0-9]+)\.service ]]; then
            local id="${BASH_REMATCH[1]}"
            echo "   [$count] Tunnel $id"; available_ids+=("$id"); ((count++))
        fi
    done
    echo -ne "\n   Select: "; read idx
    if [[ -z "${available_ids[$idx]}" ]]; then return; fi
    local tid="${available_ids[$idx]}"; nano "/etc/systemd/system/gre-tun-${tid}.service"
    systemctl daemon-reload; systemctl restart "gre-tun-${tid}"
    echo -e "   ${GREEN}✔ Updated.${NC}"; sleep 1
}

# ==================================================
#   🆕 SIMPLE GRE + PORT FORWARDING (Updated v12)
# ==================================================

setup_simple_gre() {
    local SIMPLE_SCRIPT="/opt/simple_gre_script.sh"
    local SIMPLE_SERVICE="/etc/systemd/system/simple-gre.service"

    echo -e "\n${BLUE}➤ SIMPLE GRE + PORT MAPPING${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    
    # Detailed Guide (Updated for Port Mapping)
    echo -e "${PURPLE}┌──[ 💡 HELP: MANUAL METHOD & PORT MAPPING ]───────────────────────┐${NC}"
    echo -e "${PURPLE}│${NC} This method connects two servers and forwards specific traffic."
    echo -e "${PURPLE}│${NC} "
    echo -e "${PURPLE}│${NC} 1. ${BOLD}IRAN (Sender):${NC} Forwards traffic from Local Port -> Remote Port."
    echo -e "${PURPLE}│${NC}    Example: Receive on 443 (Iran) -> Send to 8443 (Kharej)."
    echo -e "${PURPLE}│${NC}    * NAT is restricted to the tunnel interface (Safe Mode)."
    echo -e "${PURPLE}│${NC} "
    echo -e "${PURPLE}│${NC} 2. ${BOLD}KHAREJ (Receiver):${NC} Just accepts the connection."
    echo -e "${PURPLE}└──────────────────────────────────────────────────────────────────┘${NC}"

    echo -e " ${BOLD}[1] ${CYAN}Sender (IRAN)${NC}"
    echo -e " ${BOLD}[2] ${CYAN}Receiver (KHAREJ)${NC}"
    echo -ne "\n ${WHITE}Select Role:${NC} "
    read role_choice

    if [[ "$role_choice" != "1" && "$role_choice" != "2" ]]; then
        echo -e "   ${RED}Invalid option.${NC}"
        return
    fi

    local remote_ip=""
    while true; do
        if [[ "$role_choice" == "1" ]]; then
            echo -ne "   ${WHITE}➤ Enter Remote (Kharej) IP:${NC} "
        else
            echo -ne "   ${WHITE}➤ Enter Remote (Iran) IP:${NC} "
        fi
        read remote_ip
        if validate_ipv4 "$remote_ip"; then break; fi
        echo -e "     ${RED}❌ Invalid IPv4.${NC}"
    done

    # Local IP Detect (Bind IP)
    local local_bind_ip=$(get_bind_ip "$remote_ip")
    echo -e "     ${GREY}ℹ️  Using Local Bind IP: ${WHITE}$local_bind_ip${NC}"

    # -- Generate Content --
    cat <<EOF > "$SIMPLE_SCRIPT"
#!/bin/bash
# Generated by GRE Master - Simple Mode v12
EOF
    chmod +x "$SIMPLE_SCRIPT"

    if [[ "$role_choice" == "1" ]]; then
        # === SENDER (IRAN) LOGIC ===
        echo -ne "   ${WHITE}➤ Local Port (Receive on Iran):${NC} "
        read local_port
        echo -ne "   ${WHITE}➤ Remote Port (Send to Kharej):${NC} "
        read remote_port

        cat <<EOF >> "$SIMPLE_SCRIPT"
# Tunnel Setup
ip tunnel add gre_simp mode gre local $local_bind_ip remote $remote_ip ttl 255
ip addr add 172.16.200.1/30 dev gre_simp
ip link set gre_simp up

# Forwarding Setup
sysctl -w net.ipv4.ip_forward=1
# DNAT: Local Port $local_port -> Tunnel IP:Remote Port $remote_port
iptables -t nat -A PREROUTING -p tcp --dport $local_port -j DNAT --to-destination 172.16.200.2:$remote_port
iptables -t nat -A PREROUTING -p udp --dport $local_port -j DNAT --to-destination 172.16.200.2:$remote_port

# Safe Masquerade (Only for tunnel interface)
iptables -t nat -A POSTROUTING -o gre_simp -j MASQUERADE
EOF
        echo -e "\n   ${GREEN}✔ Configured as SENDER.${NC}"
        echo -e "   Traffic: ${BOLD}:$local_port (IR) ${NC}--> ${BOLD}Tunnel${NC} --> ${BOLD}:$remote_port (KH)${NC}"

    else
        # === RECEIVER (KHAREJ) LOGIC ===
        cat <<EOF >> "$SIMPLE_SCRIPT"
# Tunnel Setup
ip tunnel add gre_simp mode gre local $local_bind_ip remote $remote_ip ttl 255
ip addr add 172.16.200.2/30 dev gre_simp
ip link set gre_simp up
EOF
        echo -e "\n   ${GREEN}✔ Configured as RECEIVER.${NC}"
    fi

    # -- Create Persistence Service --
    cat <<EOF > "$SIMPLE_SERVICE"
[Unit]
Description=Simple GRE Tunnel Setup
After=network.target
[Service]
Type=oneshot
ExecStart=$SIMPLE_SCRIPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now simple-gre.service >/dev/null 2>&1
    echo -e "   ${GREEN}✔ Service Started & Enabled.${NC}"
    echo -ne "\n   Press Enter to return..."
    read
}

remove_simple_gre() {
    local SIMPLE_SCRIPT="/opt/simple_gre_script.sh"
    local SIMPLE_SERVICE="/etc/systemd/system/simple-gre.service"

    echo -e "\n${RED}➤ DELETE SIMPLE GRE (CLEANUP)${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    
    # Detailed Cleanup Guide
    echo -e "${PURPLE}┌──[ 💡 HELP: CLEANUP PROCESS ]──────────────────────────────────────┐${NC}"
    echo -e "${PURPLE}│${NC} This function will perform a deep clean of the Simple GRE configuration."
    echo -e "${PURPLE}│${NC} "
    echo -e "${PURPLE}│${NC} 1. ${BOLD}Analyze:${NC} Reads existing config to find LOCAL forwarded ports."
    echo -e "${PURPLE}│${NC} 2. ${BOLD}Revert Firewall:${NC} Deletes DNAT rules & Safe Masquerade."
    echo -e "${PURPLE}│${NC} 3. ${BOLD}Destroy Tunnel:${NC} Removes the 'gre_simp' network interface."
    echo -e "${PURPLE}│${NC} 4. ${BOLD}Remove Files:${NC} Deletes scripts and system services."
    echo -e "${PURPLE}└────────────────────────────────────────────────────────────────────┘${NC}"

    if [[ ! -f "$SIMPLE_SCRIPT" ]]; then
        echo -e "   ${YELLOW}⚠ No Simple GRE configuration found on this system.${NC}"
        read -p "   Press Enter..."
        return
    fi

    echo -e "   ${YELLOW}Are you sure you want to completely remove the Simple GRE Tunnel?${NC}"
    echo -ne "   (y/n): "
    read confirm
    if [[ "$confirm" != "y" ]]; then return; fi

    echo -e "\n   ${CYAN}Starting cleanup...${NC}"

    # 1. SMART IPTABLES CLEANUP
    # We find the LOCAL port (dport) used in PREROUTING
    local local_port_del=$(grep "dport" "$SIMPLE_SCRIPT" | head -n 1 | awk -F'--dport ' '{print $2}' | awk '{print $1}')
    # We also need to find the destination to delete exact rule
    local dest_del=$(grep "to-destination" "$SIMPLE_SCRIPT" | head -n 1 | awk -F'--to-destination ' '{print $2}' | awk '{print $1}')

    if [[ -n "$local_port_del" && -n "$dest_del" ]]; then
        echo -e "   ${GREY}Removing forwarding for Local Port: $local_port_del${NC}"
        iptables -t nat -D PREROUTING -p tcp --dport "$local_port_del" -j DNAT --to-destination "$dest_del" 2>/dev/null
        iptables -t nat -D PREROUTING -p udp --dport "$local_port_del" -j DNAT --to-destination "$dest_del" 2>/dev/null
    fi

    # Remove the specific Masquerade rule
    iptables -t nat -D POSTROUTING -o gre_simp -j MASQUERADE 2>/dev/null
    echo -e "   ${GREEN}✔ Firewall rules cleaned.${NC}"

    # 2. Stop Service
    systemctl stop simple-gre.service 2>/dev/null
    systemctl disable simple-gre.service 2>/dev/null
    rm -f "$SIMPLE_SERVICE"
    rm -f "$SIMPLE_SCRIPT"
    echo -e "   ${GREEN}✔ Service and files removed.${NC}"

    # 3. Remove Interface
    if ip link show gre_simp >/dev/null 2>&1; then
        ip link del gre_simp
        echo -e "   ${GREEN}✔ Tunnel interface (gre_simp) deleted.${NC}"
    fi

    systemctl daemon-reload
    systemctl reset-failed

    echo -e "\n   ${GREEN}✅ Cleanup Complete! No reboot required.${NC}"
    read -p "   Press Enter..."
}

# ==================================================
#   🚀 ADVANCED FORWARDING (Options 9-11)
# ==================================================

FW_SCRIPT="/usr/local/bin/gre_custom_rules.sh"
FW_SERVICE="/etc/systemd/system/gre-custom-rules.service"

ensure_forward_service() {
    if [[ ! -f "$FW_SCRIPT" ]]; then
        echo "#!/bin/bash" > "$FW_SCRIPT"
        echo "# Custom GRE Forwarding Rules" >> "$FW_SCRIPT"
        echo "sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1" >> "$FW_SCRIPT"
        echo "sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1" >> "$FW_SCRIPT"
        chmod +x "$FW_SCRIPT"
    fi

    if [[ ! -f "$FW_SERVICE" ]]; then
        cat <<EOF > "$FW_SERVICE"
[Unit]
Description=GRE Custom Forwarding Rules
After=network.target
[Service]
Type=oneshot
ExecStart=$FW_SCRIPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable gre-custom-rules.service >/dev/null 2>&1
    fi
}

setup_advanced_forwarding() {
    echo -e "\n${BLUE}➤ CUSTOM GRE FORWARDING${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    print_guide_box "Advanced Mode" "Use this to forward traffic through ${BOLD}EXISTING${NC} GRE tunnels (Option 1/2).\n  Works with both IPv4 and IPv6 Internal IPs."
    
    ensure_forward_service

    echo -ne "   ${WHITE}➤ Local Port (Entrance):${NC} "
    read l_port
    echo -ne "   ${WHITE}➤ Destination Tunnel IP (Other Side):${NC} "
    read r_ip
    echo -ne "   ${WHITE}➤ Destination Port (Remote Service):${NC} "
    read r_port

    if [[ -z "$l_port" || -z "$r_ip" || -z "$r_port" ]]; then
        echo -e "   ${RED}❌ Error: All fields are required.${NC}"; sleep 1; return
    fi

    # Determine Protocol
    local cmd="iptables"
    local proto="v4"
    if [[ "$r_ip" =~ .*:.* ]]; then
        cmd="ip6tables"
        proto="v6"
    fi

    echo -e "\n   ${YELLOW}Adding rules...${NC}"

    # Prepare Commands
    local rule1="$cmd -t nat -A PREROUTING -p tcp --dport $l_port -j DNAT --to-destination [$r_ip]:$r_port"
    local rule2="$cmd -t nat -A PREROUTING -p udp --dport $l_port -j DNAT --to-destination [$r_ip]:$r_port"
    local rule3="$cmd -t nat -A POSTROUTING -d $r_ip -p tcp --dport $r_port -j MASQUERADE"
    local rule4="$cmd -t nat -A POSTROUTING -d $r_ip -p udp --dport $r_port -j MASQUERADE"

    if [[ "$proto" == "v4" ]]; then
        # Remove brackets for IPv4
        rule1=${rule1//[\[\]]/}
        rule2=${rule2//[\[\]]/}
    fi

    # Execute Immediately
    eval "$rule1"
    eval "$rule2"
    eval "$rule3"
    eval "$rule4"

    # Save to Script
    echo "$rule1" >> "$FW_SCRIPT"
    echo "$rule2" >> "$FW_SCRIPT"
    echo "$rule3" >> "$FW_SCRIPT"
    echo "$rule4" >> "$FW_SCRIPT"

    echo -e "   ${GREEN}✔ Rules Added and Saved.${NC}"
    echo -e "   Traffic on port ${BOLD}$l_port${NC} is now forwarding to ${BOLD}$r_ip:$r_port${NC}"
    read -p "   Press Enter..."
}

edit_advanced_rules() {
    ensure_forward_service
    echo -e "\n${PURPLE}➤ EDIT FORWARDING RULES${NC}"
    if [[ ! -s "$FW_SCRIPT" ]]; then
        echo -e "   ${GREY}No rules found.${NC}"; sleep 1; return
    fi
    echo -e "   ${YELLOW}⚠ Warning: Editing manually requires knowledge of iptables syntax.${NC}"
    read -p "   Press Enter to open editor..."
    nano "$FW_SCRIPT"
    
    # Reload
    echo -e "   ${CYAN}Reloading rules...${NC}"
    bash "$FW_SCRIPT"
    echo -e "   ${GREEN}✔ Done.${NC}"; sleep 1
}

delete_advanced_rules() {
    ensure_forward_service
    echo -e "\n${RED}➤ DELETE FORWARDING RULES${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    
    if [[ ! -s "$FW_SCRIPT" ]]; then
        echo -e "   ${GREY}No custom rules found.${NC}"; sleep 1; return
    fi

    # Read lines into array
    mapfile -t lines < "$FW_SCRIPT"
    local count=0
    local valid_indices=()
    
    echo -e "   ${BOLD}ID   Rule Command${NC}"
    for i in "${!lines[@]}"; do
        local line="${lines[$i]}"
        if [[ "$line" =~ ^(iptables|ip6tables) ]]; then
            # Truncate long lines for display
            local display="${line:0:60}..."
            echo -e "   [${WHITE}$count${NC}]  ${GREY}$display${NC}"
            valid_indices[$count]=$i
            ((count++))
        fi
    done

    if [[ $count -eq 0 ]]; then echo -e "   ${GREY}No valid rules found in file.${NC}"; sleep 1; return; fi

    echo -ne "\n   ${RED}Select ID to delete:${NC} "; read idx
    
    if [[ -z "${valid_indices[$idx]}" ]]; then
        echo -e "   ${RED}Invalid selection.${NC}"; sleep 1; return
    fi

    local real_line_num=${valid_indices[$idx]}
    local command_to_run="${lines[$real_line_num]}"
    
    # 1. Remove from System (Convert -A to -D)
    local delete_cmd="${command_to_run/-A /-D }"
    echo -e "   ${YELLOW}Executing: ${delete_cmd:0:40}...${NC}"
    eval "$delete_cmd" 2>/dev/null

    # 2. Remove from File
    # sed uses 1-based indexing, array is 0-based.
    sed -i "$((real_line_num + 1))d" "$FW_SCRIPT"

    echo -e "   ${GREEN}✔ Rule deleted from System and Config.${NC}"
    read -p "   Press Enter..."
}

# ==================================================
#   🔄 MAIN LOOP
# ==================================================
install_deps

while true; do
    draw_logo
    draw_dashboard
    
    echo -e "${YELLOW} MAIN MENU${NC}"
    echo -e " ${BOLD}[1] ${CYAN}Kharej Server${NC}    ${GREY}Create tunnel (Run on Foreign VPS)${NC}"
    echo -e " ${BOLD}[2] ${CYAN}Iran Server${NC}      ${GREY}Create tunnel (Run on Iran VPS)${NC}"
    echo -e " ${BOLD}[3] ${RED}Delete Tunnel${NC}    ${GREY}Remove existing connections${NC}"
    echo -e " ${BOLD}[4] ${PURPLE}Edit Config${NC}      ${GREY}Advanced manual edit${NC}"
    echo -e " ${BOLD}[5] ${GREEN}Install Shortcut${NC} ${GREY}Add 'igre' command${NC}"
    echo -e " ${BOLD}[6] ${BLUE}Refresh Stats${NC}    ${GREY}Update IPs and Load${NC}"
    
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    echo -e " ${BOLD}[7] ${CYAN}Simple GRE IPv4${NC}  ${GREY}Manual Script + Port Mapping${NC}"
    echo -e " ${BOLD}[8] ${RED}Delete Simple${NC}    ${GREY}Clean remove of Simple GRE${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    echo -e " ${BOLD}[9] ${CYAN}Adv. Forwarding${NC}  ${GREY}Forward via Existing Tunnel IP${NC}"
    echo -e " ${BOLD}[10]${PURPLE}Edit Forwarding${NC}  ${GREY}Edit rules from Opt 9${NC}"
    echo -e " ${BOLD}[11]${RED}Del Forwarding${NC}   ${GREY}Delete rules from Opt 9${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    
    echo -e " ${BOLD}[0] ${WHITE}Exit${NC}"
    
    echo ""
    echo -ne " ${WHITE}Select Option:${NC} "
    read choice
    
    case $choice in
        1) setup_tunnel "kharej" ;;
        2) setup_tunnel "iran" ;;
        3) remove_tunnel ;;
        4) edit_tunnel ;;
        5) install_shortcut ;;
        6) rm -f "$CACHE_V4" "$CACHE_V6"; sleep 0.5 ;;
        
        # Simple GRE
        7) setup_simple_gre ;;
        8) remove_simple_gre ;;
        
        # New Advanced Forwarding
        9) setup_advanced_forwarding ;;
        10) edit_advanced_rules ;;
        11) delete_advanced_rules ;;
        
        0) clear; exit 0 ;;
        *) echo "Invalid option." ;;
    esac
done
