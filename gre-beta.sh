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
#   🆕 ADVANCED IPTABLES FORWARDING (Updated Request)
# ==================================================

FWD_SCRIPT="/opt/gre_manual_forwarding.sh"
FWD_SERVICE="/etc/systemd/system/gre-manual-fwd.service"

init_fwd_system() {
    if [[ ! -f "$FWD_SCRIPT" ]]; then
        echo "#!/bin/bash" > "$FWD_SCRIPT"
        echo "# GRE Manual Forwarding Rules" >> "$FWD_SCRIPT"
        echo "# Do not edit this header." >> "$FWD_SCRIPT"
        chmod +x "$FWD_SCRIPT"
    fi

    if [[ ! -f "$FWD_SERVICE" ]]; then
        cat <<EOF > "$FWD_SERVICE"
[Unit]
Description=GRE Manual Forwarding Rules
After=network.target

[Service]
Type=oneshot
ExecStart=$FWD_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable gre-manual-fwd.service >/dev/null 2>&1
    fi
}

add_manual_forward() {
    init_fwd_system
    echo -e "\n${BLUE}➤ ADD MANUAL FORWARDING RULE${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    echo -e "${PURPLE}ℹ️  This tool creates a persistent forwarding rule from this server${NC}"
    echo -e "${PURPLE}    to a remote GRE endpoint (Tunnel IP).${NC}"
    echo ""

    # 1. Local Port
    echo -ne "   ${WHITE}➤ Local Port (Ingress on this server):${NC} "
    read lport
    if [[ ! "$lport" =~ ^[0-9]+$ ]]; then echo -e "   ${RED}Invalid port.${NC}"; sleep 1; return; fi

    # 2. Destination IP (Remote Tunnel IP)
    echo -ne "   ${WHITE}➤ Destination IP (Remote Tunnel IP):${NC} "
    read rip
    # Simple check, we allow any format but warn if empty
    if [[ -z "$rip" ]]; then echo -e "   ${RED}IP cannot be empty.${NC}"; sleep 1; return; fi

    # 3. Destination Port
    echo -ne "   ${WHITE}➤ Destination Port (Remote Server Port):${NC} "
    read rport
    if [[ ! "$rport" =~ ^[0-9]+$ ]]; then echo -e "   ${RED}Invalid port.${NC}"; sleep 1; return; fi

    # 4. Protocol
    echo -ne "   ${WHITE}➤ Protocol (tcp/udp/both) [default: tcp]:${NC} "
    read proto
    [[ -z "$proto" ]] && proto="tcp"

    # Confirm
    echo -e "\n   ${YELLOW}Rule Summary:${NC}"
    echo -e "   Local: ${BOLD}$lport${NC}  --->  Remote: ${BOLD}$rip:$rport${NC} ($proto)"
    echo -ne "   Confirm? (y/n): "; read confirm
    [[ "$confirm" != "y" ]] && return

    # Apply Logic
    echo -e "\n   ${CYAN}Applying rules...${NC}"
    
    # Function to append safely
    append_rule() {
        local p=$1
        # ID is strictly for cleanup logic
        local rule_id="RULE_$(date +%s)_${p}_${lport}"
        
        echo "# START $rule_id" >> "$FWD_SCRIPT"
        
        local cmd_pre="iptables -t nat -A PREROUTING -p $p --dport $lport -j DNAT --to-destination $rip:$rport"
        local cmd_post="iptables -t nat -A POSTROUTING -d $rip -p $p --dport $rport -j MASQUERADE"
        
        echo "$cmd_pre" >> "$FWD_SCRIPT"
        echo "$cmd_post" >> "$FWD_SCRIPT"
        echo "# END $rule_id" >> "$FWD_SCRIPT"
        
        # Execute immediately
        $cmd_pre
        $cmd_post
    }

    if [[ "$proto" == "both" ]]; then
        append_rule "tcp"
        append_rule "udp"
    else
        append_rule "$proto"
    fi

    echo -e "   ${GREEN}✔ Rule added and saved.${NC}"
    read -p "   Press Enter..."
}

edit_manual_forward() {
    if [[ ! -f "$FWD_SCRIPT" ]]; then echo -e "   ${GREY}No forwarding rules found.${NC}"; sleep 1; return; fi
    echo -e "\n${PURPLE}➤ EDIT FORWARDING SCRIPT${NC}"
    echo -e "${YELLOW}⚠ WARNING: Advanced User Mode.${NC}"
    echo -e "   Press Enter to open Nano editor."
    read
    nano "$FWD_SCRIPT"
    echo -e "   ${CYAN}Reloading rules...${NC}"
    # Simple reload: we can't easily flush only our rules without tagging. 
    # For manual edit, we assume user knows what they did.
    # Best effort: restart service (which just runs script again, so dupes are possible if user didn't clean up).
    # Since this is advanced, we trust the user or just warn them.
    echo -e "   ${YELLOW}Note: If you removed rules, you may need to reboot or manually flush iptables to clear old ones.${NC}"
    "$FWD_SCRIPT"
    echo -e "   ${GREEN}✔ Script Executed.${NC}"; sleep 2
}

delete_manual_forward() {
    if [[ ! -f "$FWD_SCRIPT" ]]; then echo -e "   ${GREY}No forwarding rules found.${NC}"; sleep 1; return; fi
    echo -e "\n${RED}➤ DELETE FORWARDING RULE${NC}"
    
    # Grep IDs and details
    local map_file="/tmp/gre_fwd_map.txt"
    grep -n "# START RULE_" "$FWD_SCRIPT" > "$map_file"
    
    if [[ ! -s "$map_file" ]]; then
        echo -e "   ${GREY}No managed rules found in script.${NC}"; sleep 1; return
    fi
    
    echo -e "   ${BOLD}ID   Line   Rule Details${NC}"
    local idx=1
    local ids=()
    local lines=()
    
    while read -r line; do
        # Line format: 10:# START RULE_12345_tcp_8080
        local line_num=$(echo "$line" | cut -d: -f1)
        local rule_tag=$(echo "$line" | cut -d: -f2 | awk '{print $3}')
        
        # Extract info from the actual rule commands in file (next 2 lines)
        local cmd_line_num=$((line_num + 1))
        local cmd_info=$(sed -n "${cmd_line_num}p" "$FWD_SCRIPT" | grep "DNAT")
        
        # Pretty print
        local proto=$(echo "$rule_tag" | cut -d_ -f3)
        local port=$(echo "$rule_tag" | cut -d_ -f4)
        local dest=$(echo "$cmd_info" | grep -oP 'to-destination \K.*')
        
        printf "   [${WHITE}%d${NC}]  %-6s %s/%s -> %s\n" "$idx" "$line_num" "$port" "$proto" "$dest"
        ids+=("$rule_tag")
        lines+=("$line_num")
        ((idx++))
    done < "$map_file"
    
    echo -ne "\n   ${RED}Select index to delete:${NC} "; read choice
    local array_idx=$((choice - 1))
    
    if [[ -z "${ids[$array_idx]}" ]]; then echo -e "   ${RED}Invalid selection.${NC}"; sleep 1; return; fi
    
    local target_tag="${ids[$array_idx]}"
    
    echo -e "   ${YELLOW}Deleting $target_tag...${NC}"
    
    # 1. Remove from active iptables (Reverse engineering the file content for that block)
    # We find the block between START and END
    local start_ln=${lines[$array_idx]}
    local end_ln=$(grep -n "# END $target_tag" "$FWD_SCRIPT" | cut -d: -f1)
    
    if [[ -n "$start_ln" && -n "$end_ln" ]]; then
        # Execute Delete Commands (sed lines, replace -A with -D, execute)
        sed -n "$((start_ln+1)),$((end_ln-1))p" "$FWD_SCRIPT" | while read -r cmd; do
            local del_cmd=${cmd//-A/-D}
            $del_cmd 2>/dev/null
        done
        
        # 2. Remove from file
        sed -i "${start_ln},${end_ln}d" "$FWD_SCRIPT"
        echo -e "   ${GREEN}✔ Removed from config and active firewall.${NC}"
    else
        echo -e "   ${RED}Error locating rule block.${NC}"
    fi
    
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
    echo -e " ${BOLD}[9] ${BLUE}Add Manual FWD${NC}   ${GREY}Forward Port -> Existing Tunnel IP${NC}"
    echo -e " ${BOLD}[10]${PURPLE}Edit FWD Rules${NC}   ${GREY}Manually edit forwarding script${NC}"
    echo -e " ${BOLD}[11]${RED}Delete FWD Rule${NC}  ${GREY}Select and remove forwarding rule${NC}"
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
        
        # New Options
        7) setup_simple_gre ;;
        8) remove_simple_gre ;;
        
        # Requested Options
        9) add_manual_forward ;;
        10) edit_manual_forward ;;
        11) delete_manual_forward ;;
        
        0) clear; exit 0 ;;
        *) echo "Invalid option." ;;
    esac
done
