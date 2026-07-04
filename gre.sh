#!/bin/bash

# ==================================================
#   GRE MASTER v13.9 - The Ultimate Fusion (Turbo)
#   Includes: GRE Tunnel + Simple GRE + Realm Relay
#   Visuals: v8.0 Style | Logic: v13.9 (Hardened)
#   Design rule: the manager itself stays at ~0% CPU
#   and RAM - all tuning is kernel-side, no daemons,
#   no timers, no background processes added.
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
HI_CYAN='\033[0;96m'
HI_PINK='\033[0;95m'
HI_GREEN='\033[0;92m'

# --- CONSTANTS (GRE) ---
SYSCTL_FILE="/etc/sysctl.d/99-gre-tuning.conf"
CACHE_DIR="/run/gre-manager"
CACHE_V4="$CACHE_DIR/v4.cache"
CACHE_V6="$CACHE_DIR/v6.cache"
# Negative-result markers: prevents re-probing 3 APIs (up to 6s lag) on every menu redraw
CACHE_V4_MISS="$CACHE_DIR/v4.miss"
CACHE_V6_MISS="$CACHE_DIR/v6.miss"
# Shared firewall rules (GRE in + MSS clamp + forwarded return traffic), persisted at boot
GRE_FW_SCRIPT="/usr/local/bin/gre_firewall.sh"
GRE_FW_SERVICE="/etc/systemd/system/gre-firewall.service"

# --- CONSTANTS (PERFORMANCE / HIGH-LOAD, Menu 14) ---
# All opt-in and kernel-side only: no daemons, no timers, zero ongoing CPU cost.
PERF_SYSCTL_FILE="/etc/sysctl.d/98-gre-highload.conf"
PERF_MODULES_FILE="/etc/modules-load.d/gre-conntrack.conf"
PERF_SCRIPT="/usr/local/bin/gre_perf.sh"
PERF_SERVICE="/etc/systemd/system/gre-perf.service"

SHORTCUT_NAME="igre"
SHORTCUT_PATH="/usr/local/bin/$SHORTCUT_NAME"
REPO_URL="https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/gre.sh"
API_V4_LIST=("https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip")
API_V6_LIST=("https://api6.ipify.org" "https://ipv6.icanhazip.com" "https://ifconfig.co/ip")

# --- CONSTANTS (REALM) ---
REALM_CONFIG_DIR="/etc/realm"
REALM_CONFIG_FILE="/etc/realm/config.toml"
REALM_SERVICE_FILE="/etc/systemd/system/realm.service"
REALM_BIN="/usr/local/bin/realm"

# --- ROOT CHECK ---
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ Error: This script requires root privileges (sudo).${NC}"
    exit 1
fi

# Root-owned cache dir (tmpfs) - safe from /tmp tampering by other users
mkdir -p "$CACHE_DIR"
chmod 700 "$CACHE_DIR"

# ==================================================
#   🛠 UTILITIES
# ==================================================

install_deps() {
    local pkgs=""
    local tool
    for tool in curl ip grep awk sed nano iptables lsof; do
        if ! command -v "$tool" &> /dev/null; then
            # Map tool name -> apt package name (no package is literally named 'ip'/'awk')
            case $tool in
                ip)  pkgs+=" iproute2" ;;
                awk) pkgs+=" gawk" ;;
                *)   pkgs+=" $tool" ;;
            esac
        fi
    done
    if [[ -n "$pkgs" ]]; then
        if ! command -v apt-get &> /dev/null; then
            echo -e "${YELLOW}⚠ Non-Debian system detected. Install these manually:${NC}$pkgs"
            sleep 3
            return
        fi
        clear
        echo -e "${GREY}📦 Installing dependencies:${NC}$pkgs"
        apt-get update -qq && apt-get install -y -qq $pkgs > /dev/null
    fi
}

# --- NEW: Interactive Shortcut Install (Moved to start) ---
setup_shortcut() {
    if [ ! -s "$SHORTCUT_PATH" ]; then
        echo ""
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  ${GREEN}💿  ${BOLD}Setup '$SHORTCUT_NAME' Shortcut?${NC}"
        echo -e "  ${BLUE}Allows you to run the manager by typing '$SHORTCUT_NAME'.${NC}"
        echo ""

        echo -ne "  ${PURPLE}➤ Install (y/yes to confirm)? : ${NC}"
        read -r install_opt
        install_opt=${install_opt:-y}

        if [[ "$install_opt" =~ ^[Yy]([Ee][Ss])?$ ]]; then
            echo -e "  ${YELLOW}Downloading script to $SHORTCUT_PATH...${NC}"
            
            # Repo check
            if [ -z "$REPO_URL" ]; then
                REPO_URL="https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/gre.sh"
            fi

            # Download to a temp file first: a failed download must not clobber an existing shortcut
            local tmp_dl
            tmp_dl=$(mktemp)
            if curl -L -o "$tmp_dl" -fsSL "$REPO_URL" && [ -s "$tmp_dl" ]; then
                mv "$tmp_dl" "$SHORTCUT_PATH"
                chmod +x "$SHORTCUT_PATH"
                echo -e "  ${HI_GREEN}✔ Installed! Type '$SHORTCUT_NAME' to run.${NC}"
                sleep 2
            else
                rm -f "$tmp_dl"
                echo -e "  ${RED}✖ Download failed. Check internet connection.${NC}"
                sleep 2
            fi
        fi
    fi
}

# --- LOGIC FIXES ---
get_bind_ip() {
    local remote_ip=$1
    local bind_ip=$(ip route get "$remote_ip" | grep -oP 'src \K\S+')
    echo "$bind_ip"
}

fix_firewall() {
    if command -v ufw &> /dev/null; then
        ufw allow proto gre from any to any >/dev/null 2>&1
    fi

    # Shared idempotent rules, persisted via gre-firewall.service (plain iptables -A
    # rules die on reboot; ufw/docker set FORWARD policy to DROP which silently kills
    # all DNAT forwarding; and without MSS clamping, blocked ICMP between Iran/abroad
    # breaks PMTUD and stalls TCP inside the tunnel).
    cat <<'EOF' > "$GRE_FW_SCRIPT"
#!/bin/bash
# Generated by GRE Manager - shared firewall rules (idempotent, safe to re-run)

# Accept incoming GRE protocol (v4 + v6 transport)
iptables -C INPUT -p gre -j ACCEPT 2>/dev/null || iptables -A INPUT -p gre -j ACCEPT

# Clamp TCP MSS to path MTU: fixes stalled connections when ICMP is filtered
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# Let forwarded reply traffic through even when FORWARD policy is DROP (ufw/docker)
iptables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -C INPUT -p gre -j ACCEPT 2>/dev/null || ip6tables -A INPUT -p gre -j ACCEPT
    ip6tables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    ip6tables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || ip6tables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
fi
exit 0
EOF
    chmod +x "$GRE_FW_SCRIPT"

    if [[ ! -f "$GRE_FW_SERVICE" ]]; then
        cat <<EOF > "$GRE_FW_SERVICE"
[Unit]
Description=GRE Manager Shared Firewall Rules
After=network.target
[Service]
Type=oneshot
ExecStart=$GRE_FW_SCRIPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable gre-firewall.service >/dev/null 2>&1
    fi

    # Apply right now too (service only covers boots)
    bash "$GRE_FW_SCRIPT"
}

validate_ipv4() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        local octet
        for octet in "${BASH_REMATCH[@]:1}"; do
            (( 10#$octet <= 255 )) || return 1
        done
        return 0
    fi
    return 1
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

validate_ipv6() {
    local ip=$1
    [[ -z "$ip" ]] && return 1
    ip -6 route get "$ip" >/dev/null 2>&1
    return $?
}

detect_local_ips() {
    LOCAL_V4=""
    if [[ -f "$CACHE_V4" ]] && [[ $(find "$CACHE_V4" -mmin -60 2>/dev/null) ]]; then
        LOCAL_V4=$(cat "$CACHE_V4")
        validate_ipv4 "$LOCAL_V4" || LOCAL_V4=""
    fi
    if [[ -z "$LOCAL_V4" ]]; then
        # Skip the API probes (3 x 2s timeout) if they failed within the last 10 min
        if ! [[ -f "$CACHE_V4_MISS" && $(find "$CACHE_V4_MISS" -mmin -10 2>/dev/null) ]]; then
            for api in "${API_V4_LIST[@]}"; do
                LOCAL_V4=$(curl -s --max-time 2 -4 "$api")
                if validate_ipv4 "$LOCAL_V4"; then echo "$LOCAL_V4" > "$CACHE_V4"; rm -f "$CACHE_V4_MISS"; break; fi
            done
            validate_ipv4 "$LOCAL_V4" || touch "$CACHE_V4_MISS"
        fi
        if ! validate_ipv4 "$LOCAL_V4"; then
            LOCAL_V4=$(hostname -I | tr ' ' '\n' | grep -vE '^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))' | head -n 1)
        fi
    fi

    LOCAL_V6=""
    if [[ -f "$CACHE_V6" ]] && [[ $(find "$CACHE_V6" -mmin -60 2>/dev/null) ]]; then
        LOCAL_V6=$(cat "$CACHE_V6")
        [[ "$LOCAL_V6" =~ ^[0-9a-fA-F:]+$ ]] || LOCAL_V6=""
    fi
    if [[ -z "$LOCAL_V6" ]]; then
        if ! [[ -f "$CACHE_V6_MISS" && $(find "$CACHE_V6_MISS" -mmin -10 2>/dev/null) ]]; then
            for api in "${API_V6_LIST[@]}"; do
                LOCAL_V6=$(curl -s --max-time 2 -6 "$api")
                if [[ "$LOCAL_V6" =~ ^[0-9a-fA-F:]+$ ]] && validate_ipv6 "$LOCAL_V6"; then echo "$LOCAL_V6" > "$CACHE_V6"; rm -f "$CACHE_V6_MISS"; break; fi
            done
            { [[ "$LOCAL_V6" =~ ^[0-9a-fA-F:]+$ ]] && validate_ipv6 "$LOCAL_V6"; } || touch "$CACHE_V6_MISS"
        fi
        if ! [[ "$LOCAL_V6" =~ ^[0-9a-fA-F:]+$ ]] || ! validate_ipv6 "$LOCAL_V6"; then
            LOCAL_V6=$(ip -6 -o addr show scope global | grep -v "temporary" | grep -v "deprecated" | awk '{print $4}' | cut -d/ -f1 | head -n 1)
        fi
    fi
}

get_active_tunnels() {
    # Match by name, not "type gre": ip6gre tunnels are a different netlink type and
    # would be missed, while the kernel's fallback device gre0 must not be counted.
    # TIDs are 1-250, so [1-9][0-9]{0,2} covers all of ours and excludes gre0.
    ip -o link show 2>/dev/null | grep -cE ': gre(-out-)?[1-9][0-9]{0,2}[@:]'
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
    echo -e "         ${GREY}VPN TUNNEL MANAGER  |  v13.9${NC}"
    echo ""
}

draw_dashboard() {
    detect_local_ips
    local show_v4="$LOCAL_V4"; [[ -z "$show_v4" ]] && show_v4="${RED}Not Detected${NC}"
    local show_v6="${GREEN}Online${NC}"; [[ -z "$LOCAL_V6" ]] && show_v6="${GREY}Offline${NC}"
    local tunnels=$(get_active_tunnels)
    local load=$(cat /proc/loadavg | awk '{print $1}')
    
    # Check Realm Status for Dashboard
    local realm_status="${RED}OFF${NC}"
    if systemctl is-active --quiet realm; then realm_status="${GREEN}ON${NC}"; fi

    # High-Load profile state (file check only - zero cost)
    local turbo_status="${GREY}OFF${NC}"
    [[ -f "$PERF_SYSCTL_FILE" ]] && turbo_status="${HI_GREEN}ON${NC}"

    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    printf "${CYAN}║${NC}  🌐 IPv4: %-19b   IPv6: %-22b ${CYAN}║${NC}\n" "${WHITE}$show_v4${NC}" "$show_v6"
    printf "${CYAN}║${NC}  📊 Load: %-19b   🚀 Tunnels: %-19b ${CYAN}║${NC}\n" "${WHITE}$load${NC}" "${YELLOW}$tunnels${NC}"
    printf "${CYAN}║${NC}  🦀 Realm: %-18b  ⚡ Turbo: %-22b ${CYAN}║${NC}\n" "$realm_status" "$turbo_status"
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
    # Always rewrite: the file is owned by this script, and rewriting lets upgrades
    # deliver new tuning to existing installs (previously old files were kept forever)
    cat <<EOF > "$SYSCTL_FILE"
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# Larger buffers for high-BDP paths (Iran <-> abroad has high RTT)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOF
    sysctl -p "$SYSCTL_FILE" > /dev/null 2>&1
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
        read -r r_ip
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
        echo -ne "   ${WHITE}➤ Tunnel ID:${NC} "; read -r tid
        if [[ "$tid" =~ ^[0-9]+$ ]] && (( 10#$tid >= 1 && 10#$tid <= 250 )); then
            tid=$(( 10#$tid ))
            break
        fi
        echo -e "     ${RED}❌ Invalid. Enter a number between 1 and 250.${NC}"
    done

    # Optional MTU (config-time choice, zero runtime cost). 1430 is the safe default;
    # clean paths can go up to 1472 (GRE/IPv4+key) or 1452 (ip6gre+key) for ~3% more
    # payload per packet. MSS clamping protects TCP against a too-high choice anyway.
    local mtu_max=1472; [[ "$transport_proto" == "6" ]] && mtu_max=1452
    echo ""
    print_guide_box "MTU (Optional)" "Press ${BOLD}Enter${NC} for the safe default 1430. On clean paths ${BOLD}$mtu_max${NC} gives a bit more speed."
    local mtu_val=""
    while true; do
        echo -ne "   ${WHITE}➤ MTU [1430]:${NC} "; read -r mtu_val
        mtu_val=${mtu_val:-1430}
        if [[ "$mtu_val" =~ ^[0-9]+$ ]] && (( 10#$mtu_val >= 1280 && 10#$mtu_val <= mtu_max )); then
            mtu_val=$(( 10#$mtu_val ))
            break
        fi
        echo -e "     ${RED}❌ Invalid. Enter 1280-$mtu_max or press Enter for 1430.${NC}"
    done

    local local_bind_ip=""
    if [[ "$transport_proto" == "4" ]]; then
        local_bind_ip=$(get_bind_ip "$r_ip")
    else
        local_bind_ip="$LOCAL_V6"
    fi
    if [[ -z "$local_bind_ip" ]]; then
        echo -e "     ${RED}❌ Error: Could not determine local bind IP (no route to $r_ip).${NC}"
        read -r -p "   Press Enter..."; return
    fi

    local if_name="gre${tid}"
    [[ $role == "iran" ]] && if_name="gre-out-${tid}"
    
    # File check is reliable (list-units misses unloaded units) and much faster
    if [[ -f "/etc/systemd/system/gre-tun-${tid}.service" ]]; then
        echo -e "     ${YELLOW}⚠ Overwriting existing tunnel $tid...${NC}"
        systemctl stop "gre-keepalive-${tid}" "gre-tun-${tid}" 2>/dev/null
        rm -f "/etc/systemd/system/gre-tun-${tid}.service" "/etc/systemd/system/gre-keepalive-${tid}.service"
        # Old tunnel may have been created with the other role -> remove both names
        ip link del "gre${tid}" 2>/dev/null; ip link del "gre-out-${tid}" 2>/dev/null
        systemctl daemon-reload
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
After=network.target gre-firewall.service
Wants=gre-firewall.service
[Service]
Type=oneshot
RemainAfterExit=yes" > "$s_file"

    # 'key' lets multiple tunnels share the same local/remote pair (both sides use the same TID)
    if [[ "$transport_proto" == "6" ]]; then
        echo "ExecStart=/sbin/ip -6 tunnel add $if_name mode ip6gre remote $r_ip local $local_bind_ip hoplimit 255 key $tid" >> "$s_file"
    else
        echo "ExecStart=/sbin/ip tunnel add $if_name mode gre remote $r_ip local $local_bind_ip ttl 255 key $tid" >> "$s_file"
    fi

    echo "ExecStart=/sbin/ip link set dev $if_name mtu $mtu_val
ExecStart=/sbin/ip link set dev $if_name up
ExecStart=/sbin/ip addr add $v4_int dev $if_name
ExecStart=/sbin/ip -6 addr add $v6_int dev $if_name
ExecStop=/sbin/ip link set dev $if_name down
ExecStop=/sbin/ip link del dev $if_name
[Install]
WantedBy=multi-user.target" >> "$s_file"

    # Watchdog: restart tunnel only after 3 consecutive lost pings (ping -c 3 succeeds if ANY reply arrives)
    # PartOf: stopping/restarting the tunnel also stops/restarts the watchdog, so a
    # manual 'systemctl stop gre-tun-X' is no longer resurrected 30s later.
    cat <<EOF > "$w_file"
[Unit]
Description=Watchdog $if_name
After=gre-tun-${tid}.service
PartOf=gre-tun-${tid}.service
[Service]
Type=simple
ExecStart=/bin/bash -c 'sleep 15; while true; do if ! ping -c 3 -W 3 $v4_rem >/dev/null 2>&1; then systemctl restart gre-tun-${tid}; sleep 20; fi; sleep 10; done'
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "gre-tun-${tid}" >/dev/null 2>&1
    systemctl enable --now "gre-keepalive-${tid}" >/dev/null 2>&1

    # If the High-Load profile is active, spread this new interface across CPUs too
    [[ -x "$PERF_SCRIPT" ]] && "$PERF_SCRIPT" >/dev/null 2>&1

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
    echo -e "   ${YELLOW}⚠ Both servers must be set up with this script version (tunnels are keyed).${NC}"
    print_guide_box "Next Step" "Copy the ${GREEN}Internal IPv4${NC} above and use it in your Panel (3x-ui/Hiddify) as the destination."
    echo -ne "\n   Press Enter to return to menu..."
    read -r
}

remove_tunnel() {
    echo -e "\n${RED}➤ DELETE MENU${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    local files=(/etc/systemd/system/gre-tun-*.service)
    if [[ ! -e "${files[0]}" ]]; then echo -e "   ${GREY}No active tunnels found.${NC}"; read -r -p "   Press Enter..."; return; fi
    
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
    echo -ne "\n   ${RED}Select index to delete:${NC} "; read -r idx
    # Numeric check is mandatory: a non-numeric bash array subscript evaluates to 0
    # and would silently select (and delete!) the first tunnel in the list.
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ -z "${available_ids[$idx]}" ]]; then
        echo -e "   ${RED}Invalid selection.${NC}"; sleep 1; return
    fi
    local tid="${available_ids[$idx]}"
    echo -e "\n   ${YELLOW}Deleting Tunnel $tid...${NC}"
    systemctl stop "gre-keepalive-${tid}" "gre-tun-${tid}" 2>/dev/null
    systemctl disable "gre-keepalive-${tid}" "gre-tun-${tid}" 2>/dev/null
    rm -f "/etc/systemd/system/gre-keepalive-${tid}.service" "/etc/systemd/system/gre-tun-${tid}.service"
    ip link del "gre${tid}" 2>/dev/null; ip link del "gre-out-${tid}" 2>/dev/null
    systemctl daemon-reload; systemctl reset-failed
    echo -e "   ${GREEN}✔ Deleted successfully.${NC}"
    echo -e "   ${GREY}ℹ Forwarding rules pointing at this tunnel (Option 9) are not auto-removed - use Option 11.${NC}"
    read -r -p "   Press Enter..."
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
    echo -ne "\n   Select: "; read -r idx
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ -z "${available_ids[$idx]}" ]]; then return; fi
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
    
    echo -e " ${BOLD}[1] ${CYAN}Sender (IRAN)${NC}"
    echo -e " ${BOLD}[2] ${CYAN}Receiver (KHAREJ)${NC}"
    echo -ne "\n ${WHITE}Select Role:${NC} "
    read -r role_choice

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
        read -r remote_ip
        if validate_ipv4 "$remote_ip"; then break; fi
        echo -e "     ${RED}❌ Invalid IPv4.${NC}"
    done

    # Local IP Detect (Bind IP)
    local local_bind_ip=$(get_bind_ip "$remote_ip")
    if [[ -z "$local_bind_ip" ]]; then
        echo -e "     ${RED}❌ Error: Could not determine local bind IP (no route to $remote_ip).${NC}"
        read -r -p "   Press Enter..."; return
    fi
    echo -e "     ${GREY}ℹ️  Using Local Bind IP: ${WHITE}$local_bind_ip${NC}"

    # GRE protocol must be open on both roles (was previously never done for Simple mode)
    fix_firewall

    # -- Generate Content --
    cat <<EOF > "$SIMPLE_SCRIPT"
#!/bin/bash
# Generated by GRE Master - Simple Mode v12
EOF
    chmod +x "$SIMPLE_SCRIPT"

    if [[ "$role_choice" == "1" ]]; then
        # === SENDER (IRAN) LOGIC ===
        while true; do
            echo -ne "   ${WHITE}➤ Local Port (Receive on Iran):${NC} "
            read -r local_port
            validate_port "$local_port" && break
            echo -e "     ${RED}❌ Invalid port (1-65535).${NC}"
        done
        while true; do
            echo -ne "   ${WHITE}➤ Remote Port (Send to Kharej):${NC} "
            read -r remote_port
            validate_port "$remote_port" && break
            echo -e "     ${RED}❌ Invalid port (1-65535).${NC}"
        done

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

# Allow the forwarded traffic even when FORWARD policy is DROP (ufw/docker)
iptables -C FORWARD -d 172.16.200.2 -p tcp --dport $remote_port -j ACCEPT 2>/dev/null || iptables -I FORWARD -d 172.16.200.2 -p tcp --dport $remote_port -j ACCEPT
iptables -C FORWARD -d 172.16.200.2 -p udp --dport $remote_port -j ACCEPT 2>/dev/null || iptables -I FORWARD -d 172.16.200.2 -p udp --dport $remote_port -j ACCEPT

# Safe Masquerade (Only for tunnel interface)
iptables -t nat -A POSTROUTING -o gre_simp -j MASQUERADE
EOF
        echo -e "\n   ${GREEN}✔ Configured as SENDER.${NC}"

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
    read -r
}

remove_simple_gre() {
    local SIMPLE_SCRIPT="/opt/simple_gre_script.sh"
    local SIMPLE_SERVICE="/etc/systemd/system/simple-gre.service"

    echo -e "\n${RED}➤ DELETE SIMPLE GRE (CLEANUP)${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    
    if [[ ! -f "$SIMPLE_SCRIPT" ]]; then
        echo -e "   ${YELLOW}⚠ No Simple GRE configuration found on this system.${NC}"
        read -r -p "   Press Enter..."
        return
    fi

    echo -e "   ${YELLOW}Are you sure you want to completely remove the Simple GRE Tunnel?${NC}"
    echo -ne "   (y/n): "
    read -r confirm
    if [[ "$confirm" != "y" ]]; then return; fi

    echo -e "\n   ${CYAN}Starting cleanup...${NC}"

    # 1. SMART IPTABLES CLEANUP
    local local_port_del=$(grep "dport" "$SIMPLE_SCRIPT" | head -n 1 | awk -F'--dport ' '{print $2}' | awk '{print $1}')
    local dest_del=$(grep "to-destination" "$SIMPLE_SCRIPT" | head -n 1 | awk -F'--to-destination ' '{print $2}' | awk '{print $1}')

    if [[ -n "$local_port_del" && -n "$dest_del" ]]; then
        echo -e "   ${GREY}Removing forwarding for Local Port: $local_port_del${NC}"
        iptables -t nat -D PREROUTING -p tcp --dport "$local_port_del" -j DNAT --to-destination "$dest_del" 2>/dev/null
        iptables -t nat -D PREROUTING -p udp --dport "$local_port_del" -j DNAT --to-destination "$dest_del" 2>/dev/null
        # FORWARD accepts added by the generated script (dest looks like 172.16.200.2:PORT)
        local rport_del="${dest_del##*:}"
        if [[ -n "$rport_del" ]]; then
            iptables -D FORWARD -d 172.16.200.2 -p tcp --dport "$rport_del" -j ACCEPT 2>/dev/null
            iptables -D FORWARD -d 172.16.200.2 -p udp --dport "$rport_del" -j ACCEPT 2>/dev/null
        fi
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
    read -r -p "   Press Enter..."
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
    print_guide_box "Advanced Mode" "Use this to forward traffic through ${BOLD}EXISTING${NC} GRE tunnels (Option 1/2).\n  Works with Just IPv4 Internal IPs.\n (Don't Use IPv6)"
    
    ensure_forward_service

    echo -ne "   ${WHITE}➤ Local Port (Entrance):${NC} "
    read -r l_port
    echo -ne "   ${WHITE}➤ Destination Tunnel IP (Other Side):${NC} "
    read -r r_ip
    echo -ne "   ${WHITE}➤ Destination Port (Remote Service):${NC} "
    read -r r_port

    if [[ -z "$l_port" || -z "$r_ip" || -z "$r_port" ]]; then
        echo -e "   ${RED}❌ Error: All fields are required.${NC}"; sleep 1; return
    fi

    if ! validate_port "$l_port" || ! validate_port "$r_port"; then
        echo -e "   ${RED}❌ Error: Ports must be numbers between 1 and 65535.${NC}"; sleep 1; return
    fi

    # DNAT in PREROUTING hijacks the port even if a local service (e.g. sshd) uses it
    if ss -H -tln "( sport = :$l_port )" 2>/dev/null | grep -q .; then
        echo -e "\n   ${YELLOW}⚠ Port $l_port is in use by a LOCAL service on this server.${NC}"
        echo -e "   ${YELLOW}  Forwarding will hijack it. If that is your SSH port, you WILL lose access!${NC}"
        echo -ne "   ${WHITE}Continue anyway? (y/n): ${NC}"
        read -r hijack_ok
        if ! [[ "$hijack_ok" =~ ^[Yy]$ ]]; then echo -e "   ${GREY}Cancelled.${NC}"; sleep 1; return; fi
    fi

    # Determine Protocol + validate destination IP
    local cmd="iptables"
    local dest="$r_ip:$r_port"
    if [[ "$r_ip" == *:* ]]; then
        if ! [[ "$r_ip" =~ ^[0-9a-fA-F:]+$ ]]; then
            echo -e "   ${RED}❌ Error: Invalid IPv6 address.${NC}"; sleep 1; return
        fi
        cmd="ip6tables"
        dest="[$r_ip]:$r_port"
    elif ! validate_ipv4 "$r_ip"; then
        echo -e "   ${RED}❌ Error: Invalid IPv4 address.${NC}"; sleep 1; return
    fi

    echo -e "\n   ${YELLOW}Adding rules...${NC}"

    # Make sure MSS clamp + RELATED,ESTABLISHED accept are in place (ufw/docker safe)
    fix_firewall

    # Execute immediately + persist (inputs validated above, no eval needed)
    local fw_proto
    for fw_proto in tcp udp; do
        "$cmd" -t nat -A PREROUTING -p "$fw_proto" --dport "$l_port" -j DNAT --to-destination "$dest"
        "$cmd" -t nat -A POSTROUTING -d "$r_ip" -p "$fw_proto" --dport "$r_port" -j MASQUERADE
        # New connections traverse FORWARD; -I beats a DROP policy (ufw/docker)
        "$cmd" -I FORWARD -d "$r_ip" -p "$fw_proto" --dport "$r_port" -j ACCEPT
        echo "$cmd -t nat -A PREROUTING -p $fw_proto --dport $l_port -j DNAT --to-destination $dest" >> "$FW_SCRIPT"
        echo "$cmd -t nat -A POSTROUTING -d $r_ip -p $fw_proto --dport $r_port -j MASQUERADE" >> "$FW_SCRIPT"
        echo "$cmd -I FORWARD -d $r_ip -p $fw_proto --dport $r_port -j ACCEPT" >> "$FW_SCRIPT"
    done

    # Default conntrack table (~65k) fills up with many concurrent NATed users
    if ! grep -q "nf_conntrack_max" "$FW_SCRIPT"; then
        echo "sysctl -w net.netfilter.nf_conntrack_max=262144 >/dev/null 2>&1" >> "$FW_SCRIPT"
        sysctl -w net.netfilter.nf_conntrack_max=262144 >/dev/null 2>&1
    fi

    echo -e "   ${GREEN}✔ Rules Added and Saved.${NC}"
    echo -e "   Traffic on port ${BOLD}$l_port${NC} is now forwarding to ${BOLD}$r_ip:$r_port${NC}"
    read -r -p "   Press Enter..."
}

edit_advanced_rules() {
    ensure_forward_service
    echo -e "\n${PURPLE}➤ EDIT FORWARDING RULES${NC}"
    if [[ ! -s "$FW_SCRIPT" ]]; then
        echo -e "   ${GREY}No rules found.${NC}"; sleep 1; return
    fi
    echo -e "   ${YELLOW}⚠ Warning: Editing manually requires knowledge of iptables syntax.${NC}"

    # Snapshot the rules that are currently live, so we can remove them before
    # re-running the file. Re-running alone would append duplicates forever.
    local old_rules=()
    mapfile -t old_rules < <(grep -E '^(iptables|ip6tables) ' "$FW_SCRIPT")

    read -r -p "   Press Enter to open editor..."
    nano "$FW_SCRIPT"

    # Reload
    echo -e "   ${CYAN}Reloading rules...${NC}"
    local line del_cmd
    for line in "${old_rules[@]}"; do
        del_cmd="${line/-A /-D }"
        del_cmd="${del_cmd/-I /-D }"
        # Word-splitting execution on purpose (no eval: metachars stay literal)
        $del_cmd 2>/dev/null
    done
    bash "$FW_SCRIPT"
    echo -e "   ${GREEN}✔ Done.${NC}"; sleep 1
}

delete_advanced_rules() {
    local FW_SCRIPT="/usr/local/bin/gre_custom_rules.sh"
    local FW_SERVICE="/etc/systemd/system/gre-custom-rules.service"
    
    echo -e "\n${RED}➤ DELETE SPECIFIC RULE (Advanced)${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    
    if [[ ! -s "$FW_SCRIPT" ]]; then
        echo -e "   ${GREY}No custom rules found.${NC}"; sleep 1; return
    fi

    # خواندن فایل
    mapfile -t lines < "$FW_SCRIPT"
    local count=0
    local valid_indices=()
    
    echo -e "   ${BOLD}ID   Rule Command${NC}"
    for i in "${!lines[@]}"; do
        local line="${lines[$i]}"
        # نمایش فقط خطوطی که دستور iptables دارند
        if [[ "$line" =~ ^(iptables|ip6tables) ]]; then
            local display="${line:0:60}..."
            echo -e "   [${WHITE}$count${NC}]  ${GREY}$display${NC}"
            valid_indices[$count]=$i
            ((count++))
        fi
    done

    if [[ $count -eq 0 ]]; then 
        echo -e "   ${GREY}File exists but has no active rules.${NC}"
        echo -ne "   ${YELLOW}Remove empty file and service? (y/n): ${NC}"; read -r clean_empty
        if [[ "$clean_empty" == "y" ]]; then
             systemctl stop gre-custom-rules.service 2>/dev/null
             systemctl disable gre-custom-rules.service 2>/dev/null
             rm -f "$FW_SCRIPT" "$FW_SERVICE"
             systemctl daemon-reload
             echo -e "   ${GREEN}✔ Cleaned up empty configuration.${NC}"
        fi
        return
    fi

    echo -ne "\n   ${RED}Select ID to delete:${NC} "; read -r idx

    # Non-numeric input must be rejected BEFORE the array lookup (subscript would
    # arithmetic-evaluate to 0 and silently pick the first rule)
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ -z "${valid_indices[$idx]}" ]]; then
        echo -e "   ${RED}Invalid selection.${NC}"; sleep 1; return
    fi

    local real_line_index=${valid_indices[$idx]}
    local command_to_remove="${lines[$real_line_index]}"

    # 1. حذف آنی از فایروال سیستم (تبدیل -A/-I به -D)
    local delete_cmd="${command_to_remove/-A /-D }"
    delete_cmd="${delete_cmd/-I /-D }"

    echo -e "   ${YELLOW}Removing rule from active firewall...${NC}"
    # Word-splitting execution on purpose (no eval: shell metachars stay literal args)
    $delete_cmd 2>/dev/null

    # 2. حذف دائمی از فایل (با تطبیق دقیق متن)
    grep -v -F -x "$command_to_remove" "$FW_SCRIPT" > "${FW_SCRIPT}.tmp" && mv "${FW_SCRIPT}.tmp" "$FW_SCRIPT"
    chmod +x "$FW_SCRIPT"

    echo -e "   ${GREEN}✔ Rule removed.${NC}"

    # 3. چک کردن اینکه آیا فایل خالی شده است؟
    if ! grep -q "iptables" "$FW_SCRIPT"; then
        echo -e "\n   ${CYAN}ℹ Info: No rules left in configuration.${NC}"
        echo -ne "   ${YELLOW}Do you want to remove the empty service file too? (y/n): ${NC}"; read -r auto_clean
        if [[ "$auto_clean" == "y" ]]; then
             systemctl stop gre-custom-rules.service 2>/dev/null
             systemctl disable gre-custom-rules.service 2>/dev/null
             rm -f "$FW_SCRIPT" "$FW_SERVICE"
             systemctl daemon-reload
             echo -e "   ${GREEN}✔ Service fully removed.${NC}"
        fi
    fi
    read -r -p "   Press Enter..."
}

# ==================================================
#   🔄 wipe_all_gre_configs - 12 (TOTAL RESET)
# ==================================================

wipe_all_gre_configs() {
    echo -e "\n${RED}➤ TOTAL WIPE (RESET FORWARDING)${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    echo -e "${PURPLE}┌──[ ⚠ WARNING ]─────────────────────────────────────────────┐${NC}"
    echo -e "${PURPLE}│${NC} This will completely remove:"
    echo -e "${PURPLE}│${NC} 1. Simple GRE Tunnel (Option 7)"
    echo -e "${PURPLE}│${NC} 2. Advanced Forwarding Rules (Option 9)"
    echo -e "${PURPLE}│${NC} 3. All associated Services and Files"
    echo -e "${PURPLE}│${NC} 4. Will Reload Systemd & Network Logic"
    echo -e "${PURPLE}│${NC} ${GREY}Standard tunnels (Options 1/2) are NOT touched - use Option 3.${NC}"
    echo -e "${PURPLE}└────────────────────────────────────────────────────────────┘${NC}"

    echo -ne "   ${YELLOW}Are you sure you want to WIPE ALL Forwarding Configs? (yes/no): ${NC}"
    read -r confirm
    if [[ "$confirm" != "yes" ]]; then echo -e "   ${GREY}Cancelled.${NC}"; sleep 1; return; fi

    echo -e "\n   ${CYAN}Phase 1: Removing Simple GRE...${NC}"
    local SIMPLE_SCRIPT="/opt/simple_gre_script.sh"
    local SIMPLE_SERVICE="/etc/systemd/system/simple-gre.service"
    
    if [[ -f "$SIMPLE_SCRIPT" ]]; then
        local local_port_del=$(grep "dport" "$SIMPLE_SCRIPT" | head -n 1 | awk -F'--dport ' '{print $2}' | awk '{print $1}')
        local dest_del=$(grep "to-destination" "$SIMPLE_SCRIPT" | head -n 1 | awk -F'--to-destination ' '{print $2}' | awk '{print $1}')
        if [[ -n "$local_port_del" && -n "$dest_del" ]]; then
            iptables -t nat -D PREROUTING -p tcp --dport "$local_port_del" -j DNAT --to-destination "$dest_del" 2>/dev/null
            iptables -t nat -D PREROUTING -p udp --dport "$local_port_del" -j DNAT --to-destination "$dest_del" 2>/dev/null
            local rport_del="${dest_del##*:}"
            if [[ -n "$rport_del" ]]; then
                iptables -D FORWARD -d 172.16.200.2 -p tcp --dport "$rport_del" -j ACCEPT 2>/dev/null
                iptables -D FORWARD -d 172.16.200.2 -p udp --dport "$rport_del" -j ACCEPT 2>/dev/null
            fi
        fi
        iptables -t nat -D POSTROUTING -o gre_simp -j MASQUERADE 2>/dev/null
        
        systemctl stop simple-gre.service 2>/dev/null
        systemctl disable simple-gre.service 2>/dev/null
        rm -f "$SIMPLE_SERVICE" "$SIMPLE_SCRIPT"
        ip link del gre_simp 2>/dev/null
        echo -e "   ${GREEN}✔ Simple GRE removed.${NC}"
    else
        echo -e "   ${GREY}Simple GRE not found (Skipping).${NC}"
    fi

    echo -e "\n   ${CYAN}Phase 2: Removing Advanced Forwarding...${NC}"
    local FW_SCRIPT="/usr/local/bin/gre_custom_rules.sh"
    local FW_SERVICE="/etc/systemd/system/gre-custom-rules.service"

    if [[ -f "$FW_SCRIPT" ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^(iptables|ip6tables) ]]; then
                local del_cmd="${line/-A /-D }"
                del_cmd="${del_cmd/-I /-D }"
                # Word-splitting execution on purpose (no eval)
                $del_cmd 2>/dev/null
            fi
        done < "$FW_SCRIPT"
        
        systemctl stop gre-custom-rules.service 2>/dev/null
        systemctl disable gre-custom-rules.service 2>/dev/null
        rm -f "$FW_SCRIPT" "$FW_SERVICE"
        echo -e "   ${GREEN}✔ Advanced Rules removed.${NC}"
    else
        echo -e "   ${GREY}Advanced Rules not found (Skipping).${NC}"
    fi

    echo -e "\n   ${CYAN}Phase 3: System Refresh...${NC}"
    systemctl daemon-reload
    systemctl reset-failed
    
    echo -e "\n   ${GREEN}✅ ALL DONE! System is clean.${NC}"
    read -r -p "   Press Enter..."
}

# ==================================================
#   ⚡ PERFORMANCE / HIGH-LOAD MODULE - 14
#   Opt-in, kernel-side only. Adds NO daemons, NO
#   timers, NO background processes. RAM is consumed
#   only by real connections (conntrack entries).
# ==================================================

perf_section_title() { echo -e "\n  ${BOLD}${HI_CYAN}:: $1 ::${NC}"; }

# Writes the boot-time tuning script + service (RPS spreading + GRE NOTRACK).
# The script runs once at boot and exits - zero ongoing cost.
perf_install_tools() {
    cat <<'EOF' > "$PERF_SCRIPT"
#!/bin/bash
# Generated by GRE Manager - High-Load tuning (idempotent, runs once and exits)
shopt -s nullglob

# At boot, give gre-tun-*.service a moment to create the tunnel devices
[[ "$1" == "boot" ]] && sleep 5

# --- RPS/RFS ---
# NIC RSS hashes only the OUTER header of GRE (fixed src/dst, no ports), so all
# tunnel traffic lands on ONE core. RPS re-hashes the inner flows and spreads
# softirq across all cores - this is the main multi-core win for 10k+ users.
cores=$(nproc)
if (( cores > 1 )); then
    (( cores > 32 )) && cores=32
    mask=$(printf '%x' $(( (1 << cores) - 1 )))
    echo 32768 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null
    for q in /sys/class/net/gre*/queues/rx-*/rps_cpus; do
        echo "$mask" > "$q" 2>/dev/null
    done
    for q in /sys/class/net/gre*/queues/rx-*/rps_flow_cnt; do
        echo 4096 > "$q" 2>/dev/null
    done
fi

# --- NOTRACK for outer GRE carrier packets ---
# The encapsulated (inner) traffic is still fully tracked for NAT; the outer
# proto-47 packets don't need tracking. Saves a conntrack lookup per packet.
# Our INPUT accept for gre is stateless, so this is safe.
iptables -t raw -C PREROUTING -p gre -j NOTRACK 2>/dev/null || iptables -t raw -A PREROUTING -p gre -j NOTRACK
iptables -t raw -C OUTPUT -p gre -j NOTRACK 2>/dev/null || iptables -t raw -A OUTPUT -p gre -j NOTRACK
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -t raw -C PREROUTING -p gre -j NOTRACK 2>/dev/null || ip6tables -t raw -A PREROUTING -p gre -j NOTRACK
    ip6tables -t raw -C OUTPUT -p gre -j NOTRACK 2>/dev/null || ip6tables -t raw -A OUTPUT -p gre -j NOTRACK
fi
exit 0
EOF
    chmod +x "$PERF_SCRIPT"

    if [[ ! -f "$PERF_SERVICE" ]]; then
        cat <<EOF > "$PERF_SERVICE"
[Unit]
Description=GRE Manager High-Load Tuning (RPS + NOTRACK)
After=network.target
[Service]
Type=simple
ExecStart=$PERF_SCRIPT boot
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable gre-perf.service >/dev/null 2>&1
    fi
}

perf_apply_profile() {
    perf_section_title "APPLY HIGH-LOAD PROFILE"
    echo -e "  ${GREY}Kernel-side tuning only. No new processes. CPU usage does not${NC}"
    echo -e "  ${GREY}increase (it drops per-core thanks to RPS). RAM below is the${NC}"
    echo -e "  ${GREY}worst case, used ONLY when the table is actually full.${NC}"
    echo ""
    echo -e "  ${BOLD}[1]${NC} HIGH     ${CYAN}~10k-50k users${NC}   conntrack 524k   ${GREY}(peak RAM if full: ~180 MB, needs 1GB+)${NC}"
    echo -e "  ${BOLD}[2]${NC} EXTREME  ${CYAN}100k+ users${NC}      conntrack 1048k  ${GREY}(peak RAM if full: ~400 MB, needs 2GB+)${NC}"
    echo -e "  ${BOLD}[0]${NC} Cancel"
    echo ""
    echo -ne "  ${HI_PINK}➤ Select tier : ${NC}"
    read -r tier

    local ct_max=0 ram_need=0
    case "$tier" in
        1) ct_max=524288;  ram_need=1024 ;;
        2) ct_max=1048576; ram_need=2048 ;;
        *) return ;;
    esac
    local ct_buckets=$(( ct_max / 4 ))

    # RAM sanity check (worst-case table usage ~320B per entry)
    local mem_mb
    mem_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null)
    if [[ -n "$mem_mb" ]] && (( mem_mb < ram_need )); then
        echo -e "\n  ${YELLOW}⚠ This server has ${mem_mb}MB RAM; this tier is sized for ${ram_need}MB+.${NC}"
        echo -e "  ${YELLOW}  If the conntrack table ever fills completely, RAM may run out.${NC}"
        echo -ne "  ${WHITE}Continue anyway? (y/n): ${NC}"
        read -r ram_ok
        [[ "$ram_ok" =~ ^[Yy]$ ]] || return
    fi

    echo -e "\n  ${YELLOW}Applying...${NC}"

    # nf_conntrack must be loaded before systemd-sysctl at boot, or the
    # net.netfilter.* keys below silently fail to apply
    echo "nf_conntrack" > "$PERF_MODULES_FILE"
    modprobe nf_conntrack 2>/dev/null

    cat <<EOF > "$PERF_SYSCTL_FILE"
# GRE Manager High-Load profile (Menu 14). Remove via menu, or just delete this file.
net.netfilter.nf_conntrack_max = $ct_max
net.netfilter.nf_conntrack_buckets = $ct_buckets
# Idle established flows expire after 2h instead of 5 days - keeps the table small
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
# Full ephemeral range: needed by NAT and realm at high connection counts
net.ipv4.ip_local_port_range = 1024 65535
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 8192
# Proxy-friendly TCP: don't reset cwnd on idle, probe MTU on blackholes
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
EOF
    sysctl -p "$PERF_SYSCTL_FILE" >/dev/null 2>&1

    # Hash buckets: writable as module param on kernels where the sysctl is read-only
    echo "$ct_buckets" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null

    perf_install_tools
    "$PERF_SCRIPT" >/dev/null 2>&1

    echo -e "\n  ${HI_GREEN}✔ Profile active.${NC}"
    echo -e "  ${GREY}- conntrack table: $ct_max entries (RAM grows only with real connections)${NC}"
    echo -e "  ${GREY}- RPS: tunnel load now spreads across $(nproc) CPU core(s)${NC}"
    echo -e "  ${GREY}- NOTRACK: outer GRE packets skip conntrack (less CPU per packet)${NC}"
    echo -e "  ${GREY}- Zero new background processes were added.${NC}"
    read -r -p "  Press Enter..."
}

perf_remove_profile() {
    perf_section_title "REMOVE HIGH-LOAD PROFILE"
    if [[ ! -f "$PERF_SYSCTL_FILE" && ! -f "$PERF_SCRIPT" ]]; then
        echo -e "  ${GREY}Profile is not installed.${NC}"; sleep 1; return
    fi
    echo -ne "  ${YELLOW}Revert to defaults? (y/n): ${NC}"
    read -r c
    [[ "$c" == "y" ]] || return

    rm -f "$PERF_SYSCTL_FILE" "$PERF_MODULES_FILE"
    systemctl disable gre-perf.service >/dev/null 2>&1
    rm -f "$PERF_SERVICE" "$PERF_SCRIPT"
    systemctl daemon-reload

    # Best-effort runtime revert (fully back to distro defaults after a reboot)
    iptables -t raw -D PREROUTING -p gre -j NOTRACK 2>/dev/null
    iptables -t raw -D OUTPUT -p gre -j NOTRACK 2>/dev/null
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -t raw -D PREROUTING -p gre -j NOTRACK 2>/dev/null
        ip6tables -t raw -D OUTPUT -p gre -j NOTRACK 2>/dev/null
    fi
    local q
    for q in /sys/class/net/gre*/queues/rx-*/rps_cpus; do
        [[ -e "$q" ]] && echo 0 > "$q" 2>/dev/null
    done
    sysctl -w net.netfilter.nf_conntrack_max=262144 >/dev/null 2>&1
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=432000 >/dev/null 2>&1
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=120 >/dev/null 2>&1
    sysctl -w net.ipv4.ip_local_port_range="32768 60999" >/dev/null 2>&1

    echo -e "  ${HI_GREEN}✔ Removed. A reboot restores every kernel default completely.${NC}"
    read -r -p "  Press Enter..."
}

perf_show_status() {
    clear
    perf_section_title "PERFORMANCE STATUS"

    local cores profile_state="${GREY}OFF${NC}"
    cores=$(nproc 2>/dev/null || echo 1)
    [[ -f "$PERF_SYSCTL_FILE" ]] && profile_state="${HI_GREEN}ACTIVE${NC}"

    echo -e "  High-Load Profile : $profile_state"
    echo -e "  CPU Cores         : ${WHITE}$cores${NC}"
    echo -e "  Congestion / Qdisc: ${WHITE}$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) / $(sysctl -n net.core.default_qdisc 2>/dev/null)${NC}"

    # conntrack usage (the real capacity limit for NATed users)
    if [[ -f /proc/sys/net/netfilter/nf_conntrack_count ]]; then
        local ct_c ct_m ct_pct
        ct_c=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
        ct_m=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
        ct_pct=0; (( ct_m > 0 )) && ct_pct=$(( ct_c * 100 / ct_m ))
        local ct_color=$GREEN; (( ct_pct >= 70 )) && ct_color=$YELLOW; (( ct_pct >= 90 )) && ct_color=$RED
        echo -e "  Connections (NAT) : ${ct_color}${ct_c}${NC} / ${ct_m} (${ct_color}${ct_pct}%${NC} of table)"
    else
        echo -e "  Connections (NAT) : ${GREY}conntrack not loaded (no NAT in use)${NC}"
    fi

    # RPS state of the first tunnel queue
    local rps_state="${GREY}OFF (single-core softirq)${NC}" f
    for f in /sys/class/net/gre*/queues/rx-0/rps_cpus; do
        [[ -f "$f" ]] || continue
        if [[ -n "$(tr -d '0,\n' < "$f")" ]]; then rps_state="${HI_GREEN}ON (spread over $cores cores)${NC}"; fi
        break
    done
    echo -e "  RPS Spreading     : $rps_state"

    # Per-tunnel traffic straight from /proc (no external tools, zero cost)
    echo ""
    echo -e "  ${BOLD}Tunnel Traffic (since interface up):${NC}"
    if ! awk '$1 ~ /^(gre|gre-out-)[1-9][0-9]?[0-9]?:$/ {
        gsub(":","",$1); found=1
        rx=$2; tx=$10
        printf "   %-14s RX: %10.1f MB    TX: %10.1f MB\n", $1, rx/1048576, tx/1048576
    } END { if (!found) exit 1 }' /proc/net/dev 2>/dev/null; then
        echo -e "   ${GREY}No active tunnel interfaces.${NC}"
    fi

    # The manager's own footprint, so expectations stay explicit
    local wd_count
    wd_count=$(systemctl list-units 'gre-keepalive-*' --no-legend 2>/dev/null | grep -c keepalive)
    echo ""
    echo -e "  ${GREY}Manager footprint: $wd_count watchdog(s) (~2 MB RAM each, ~0% CPU),${NC}"
    echo -e "  ${GREY}no other background processes belong to this script.${NC}"
    echo ""
    read -r -p "  Press Enter..."
}

perf_scaling_guide() {
    clear
    perf_section_title "SCALING GUIDE (10k - 100k+ USERS)"
    echo -e "
  ${BOLD}1. The single-core trap${NC}
  ${GREY}A GRE tunnel is ONE outer flow, so NIC RSS puts ALL of its traffic on
  one CPU core (~1-3 Gbps ceiling). The High-Load profile enables RPS,
  which re-spreads the inner user flows across all cores.${NC}

  ${BOLD}2. The ~64k NAT ceiling per destination${NC}
  ${GREY}MASQUERADE allows ~64k concurrent connections per (dest IP + port).
  Past ~50k users, forward 2-4 ports with Option 9 (e.g. 443, 8443, 2053)
  to the SAME kharej service and split users between them in your panel.
  Each extra destination port adds another ~64k connection pool.${NC}

  ${BOLD}3. Capacity math${NC}
  ${GREY}Each conntrack entry costs ~320 bytes ONLY while a connection exists:
  50k users x ~5 connections = 250k entries = ~80 MB RAM in use.
  CPU: GRE has no crypto; expect a few % per 100 Mbps per core.${NC}

  ${BOLD}4. Hardware guidance${NC}
  ${GREY}Up to ~20k users: 1-2 vCPU is fine. Beyond that: 2-4+ vCPU matters
  more than RAM/clock, because softirq spreading needs real cores.
  Realm relays also benefit from the profile's wider port range.${NC}

  ${BOLD}5. What we deliberately did NOT add${NC}
  ${GREY}Metrics daemons/collectors would cost a permanent process - status is
  read on demand from /proc instead (this screen). GRE stays unencrypted
  kernel-side; an encrypted backend (WireGuard) would cost real CPU per
  packet at this scale, so it is not enabled by default.${NC}
"
    read -r -p "  Press Enter..."
}

run_perf_menu() {
    while true; do
        clear
        echo -e "${HI_CYAN}"
        echo "  ______  ____  ___  ___  ____ "
        echo " /_  __/ / / / / _ \/ _ )/ __ \\"
        echo "  / / / /_/ / / , _/ _  / /_/ /"
        echo " /_/  \____/ /_/|_/____/\____/ "
        echo -e "     ${PURPLE}H I G H - L O A D   E D I T I O N${NC}"
        echo ""
        local p_state="${GREY}OFF${NC}"
        [[ -f "$PERF_SYSCTL_FILE" ]] && p_state="${HI_GREEN}ACTIVE${NC}"
        echo -e "  PROFILE: $p_state   ${GREY}(kernel-side only - zero new processes)${NC}"
        echo ""
        echo -e "  ${HI_CYAN}[1]${NC} Performance Status ${GREY}(conntrack, RPS, per-tunnel traffic)${NC}"
        echo -e "  ${HI_CYAN}[2]${NC} Apply / Update High-Load Profile ${GREY}(10k-100k+ users)${NC}"
        echo -e "  ${HI_CYAN}[3]${NC} Remove High-Load Profile"
        echo -e "  ${HI_CYAN}[4]${NC} Scaling Guide ${GREY}(64k NAT limit, core spreading, sizing)${NC}"
        echo -e "  ${HI_CYAN}[0]${NC} Back to Main Menu"
        echo ""
        echo -ne "  ${HI_PINK}➤ Select Option : ${NC}"
        read -r popt
        case $popt in
            1) perf_show_status ;;
            2) perf_apply_profile ;;
            3) perf_remove_profile ;;
            4) perf_scaling_guide ;;
            0) return ;;
        esac
    done
}

# ==================================================
#   🦀 REALM MODULE - 13
# ==================================================

# --- Helper Functions for Realm ---
realm_confirm_yes() {
    local ans="$1"
    [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]]
}

realm_ask_input() { echo -ne "  ${HI_PINK}➤ $1 : ${NC}"; }
realm_section_title() { echo -e "\n  ${BOLD}${HI_CYAN}:: $1 ::${NC}"; }

realm_validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

realm_backup_config() { cp "$REALM_CONFIG_FILE" "${REALM_CONFIG_FILE}.bak" 2>/dev/null; }

realm_apply_config() {
    echo -e "\n${BLUE}--- Reloading Service ---${NC}"
    systemctl restart realm
    sleep 1
    if systemctl is-active --quiet realm; then
        echo -e "  ${HI_GREEN}✔ Success! Service is running.${NC}"
        read -r -p "  Press Enter to continue..."
    else
        echo -e "  ${RED}✖ Failed! Check config syntax.${NC}"
        journalctl -u realm -n 5 --no-pager
        read -r -p "  Press Enter..."
    fi
}

realm_check_port_safety() {
    local port=$1
    if grep -q "listen =.*:$port\"" "$REALM_CONFIG_FILE"; then
        echo -e "  ${RED}✖ Port $port is already in config!${NC}"; return 1
    fi
    if lsof -i :"$port" > /dev/null 2>&1; then
        echo -e "  ${RED}✖ Port $port is busy in system!${NC}"; return 1
    fi
    return 0
}

realm_install_dependencies() {
    local NEED_INSTALL=false
    if ! command -v realm &> /dev/null; then
        echo -e "${BLUE}Downloading Realm (Rust)...${NC}"
        
        local ARCH_RAW RELEASE_FILE
        ARCH_RAW=$(uname -m)
        if [[ "$ARCH_RAW" == "x86_64" ]]; then
            RELEASE_FILE="realm-x86_64-unknown-linux-gnu.tar.gz"
        elif [[ "$ARCH_RAW" == "aarch64" ]]; then
            RELEASE_FILE="realm-aarch64-unknown-linux-gnu.tar.gz"
        else
            echo -e "${RED}Unsupported architecture: $ARCH_RAW${NC}"
            return 1
        fi

        local DL_URL="https://github.com/zhboner/realm/releases/latest/download/$RELEASE_FILE"
        local TMP_DIR
        TMP_DIR=$(mktemp -d)

        echo -e "  ${YELLOW}Fetching from GitHub...${NC}"
        if curl -L -o "$TMP_DIR/realm.tar.gz" -fsSL "$DL_URL"; then
            tar -xf "$TMP_DIR/realm.tar.gz" -C "$TMP_DIR"
            mv "$TMP_DIR/realm" "$REALM_BIN"
            chmod +x "$REALM_BIN"
            rm -rf "$TMP_DIR"
            echo -e "${HI_GREEN}Realm installed successfully.${NC}"
        else
            echo -e "${RED}Download failed.${NC}"
            rm -rf "$TMP_DIR"
            return 1
        fi
    fi

    mkdir -p "$REALM_CONFIG_DIR"
    if [ ! -f "$REALM_CONFIG_FILE" ]; then
        echo "[network]" > "$REALM_CONFIG_FILE"
        echo "no_tcp = false" >> "$REALM_CONFIG_FILE"
        echo "use_udp = true" >> "$REALM_CONFIG_FILE"
        echo "" >> "$REALM_CONFIG_FILE"
    fi
    
    # Setup Service
    cat <<EOF > "$REALM_SERVICE_FILE"
[Unit]
Description=Realm Relay Service (Rust)
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
Type=simple
User=root
ExecStart=$REALM_BIN -c $REALM_CONFIG_FILE
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable realm >/dev/null 2>&1
}

realm_add_relay() {
    realm_section_title "ADD RELAY"
    echo ""
    realm_ask_input "Local Port"; read -r lport
    realm_validate_port "$lport" || { echo -e "  ${RED}Bad Port${NC}"; sleep 1; return; }
    realm_check_port_safety "$lport" || { sleep 1; return; }

    echo ""
    realm_ask_input "Remote IP"; read -r raw_ip
    # Use existing GRE normalize function? No, lets use simple one
    if [[ "$raw_ip" == *":"* && "$raw_ip" != *[* ]]; then raw_ip="[$raw_ip]"; fi
    
    realm_ask_input "Remote Port"; read -r dport
    realm_validate_port "$dport" || { echo -e "  ${RED}Bad Dest Port${NC}"; sleep 1; return; }

    realm_backup_config
    echo "" >> "$REALM_CONFIG_FILE"
    echo "[[endpoints]]" >> "$REALM_CONFIG_FILE"
    echo "listen = \"0.0.0.0:$lport\"" >> "$REALM_CONFIG_FILE"
    echo "remote = \"$raw_ip:$dport\"" >> "$REALM_CONFIG_FILE"
    realm_apply_config
}

realm_delete_relay() {
    realm_section_title "DELETE RELAY"
    
    # --- FIXED: Use Regex to extract EXACT port number, avoiding '0' ---
    mapfile -t ports < <(grep -oE "listen = \"0.0.0.0:[0-9]+\"" "$REALM_CONFIG_FILE" | cut -d: -f2 | tr -d '"' | sort -u)
    
    if [ ${#ports[@]} -eq 0 ]; then
        echo -e "  ${YELLOW}No active relays found.${NC}"; sleep 1; return
    fi

    printf "  ${BLUE}%-6s %-15s${NC}\n" "ID" "LOCAL PORT"
    echo -e "  ${BLUE}──────────────────────${NC}"
    local i=0
    for port in "${ports[@]}"; do
        printf "  ${HI_CYAN}[%d]${NC}    ${BOLD}%-15s${NC}\n" "$i" "$port"
        ((i++))
    done

    echo ""
    realm_ask_input "Enter ID (c to cancel)"; read -r idx
    [[ "$idx" == "c" || "$idx" == "C" ]] && return

    if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -lt "${#ports[@]}" ]; then
        local target_port="${ports[$idx]}"
        realm_backup_config
        
        local line_num
        line_num=$(grep -n "listen = \"0.0.0.0:$target_port\"" "$REALM_CONFIG_FILE" | cut -d: -f1 | head -n1)
        
        if [[ -n "$line_num" ]]; then
            local start_del=$((line_num - 1))
            local end_del=$((line_num + 2))
            sed -i "${start_del},${end_del}d" "$REALM_CONFIG_FILE"
            sed -i '/^\s*$/d' "$REALM_CONFIG_FILE"
            realm_apply_config
        fi
    fi
}

realm_show_config() {
    clear
    realm_section_title "REALM CONFIG (TOML)"
    if [ -f "$REALM_CONFIG_FILE" ]; then
        cat "$REALM_CONFIG_FILE" | less
    else
        echo "Config not found."
    fi
}

# --- NEW: Edit Config Function ---
realm_edit_config() {
    realm_section_title "EDIT CONFIG (MANUAL)"
    echo -e "  ${YELLOW}⚠ Note: Do not break the file structure if you want 'Delete' to work.${NC}"
    echo -e "  ${GREY}Opening config in nano...${NC}"
    sleep 1
    
    realm_backup_config
    nano "$REALM_CONFIG_FILE"
    
    realm_apply_config
}

realm_menu_uninstall() {
    realm_section_title "UNINSTALL REALM"
    realm_ask_input "Confirm (y/yes)"; read -r c
    if realm_confirm_yes "$c"; then
        systemctl stop realm >/dev/null 2>&1
        systemctl disable realm >/dev/null 2>&1
        rm -rf "$REALM_CONFIG_DIR" "$REALM_SERVICE_FILE" "$REALM_BIN"
        systemctl daemon-reload
        echo -e "\n  ${HI_GREEN}✔ Uninstalled Realm.${NC}"
        sleep 2
    fi
}

run_realm_menu() {
    realm_install_dependencies
    while true; do
        clear
        echo -e "${HI_CYAN}"
        echo "    ____  _________    __    __  ___"
        echo "   / __ \/ ____/   |  / /   /  |/  /"
        echo "  / /_/ / __/ / /| | / /   / /|_/ / "
        echo " / _, _/ /___/ ___ |/ /___/ /  / /  "
        echo "/_/ |_/_____/_/  |_/_____/_/  /_/   "
        echo -e "     ${PURPLE}R U S T   E D I T I O N${NC}"
        echo ""
        
        local r_status="${RED}OFFLINE${NC}"
        if systemctl is-active --quiet realm; then r_status="${HI_GREEN}ACTIVE${NC}"; fi
        echo -e "  STATUS: $r_status"
        echo ""
        echo -e "  ${HI_CYAN}[1]${NC} Add Relay"
        echo -e "  ${HI_CYAN}[2]${NC} Delete Relay"
        echo -e "  ${HI_CYAN}[3]${NC} Show Config"
        echo -e "  ${HI_CYAN}[4]${NC} Edit Config ${YELLOW}(Manual)${NC}"
        echo -e "  ${HI_CYAN}[5]${NC} Uninstall Realm"
        echo -e "  ${HI_CYAN}[0]${NC} Back to Main Menu"
        echo ""
        echo -ne "  ${HI_PINK}➤ Select Option : ${NC}"
        read -r ropt
        
        case $ropt in
            1) realm_add_relay ;;
            2) realm_delete_relay ;;
            3) realm_show_config ;;
            4) realm_edit_config ;;
            5) realm_menu_uninstall; return ;;
            0) return ;;
        esac
    done
}


# ==================================================
#   🔄 MAIN LOOP
# ==================================================
install_deps
setup_shortcut  # Moved shortcut setup here to run once at start

while true; do
    draw_logo
    draw_dashboard
    
    echo -e "${YELLOW} MAIN MENU${NC}"
    echo -e " ${BOLD}[1] ${CYAN}Kharej Server${NC}    ${GREY}Create tunnel (Run on Foreign VPS)${NC}"
    echo -e " ${BOLD}[2] ${CYAN}Iran Server${NC}      ${GREY}Create tunnel (Run on Iran VPS)${NC}"
    echo -e " ${BOLD}[3] ${RED}Delete Tunnel${NC}    ${GREY}Remove existing connections${NC}"
    echo -e " ${BOLD}[4] ${PURPLE}Edit Config${NC}      ${GREY}Advanced manual edit${NC}"
    echo -e " ${BOLD}[5] ${GREEN}Re-install Shortcut${NC} ${GREY}Update 'igre' command${NC}"
    echo -e " ${BOLD}[6] ${BLUE}Refresh Stats${NC}    ${GREY}Update IPs and Load${NC}"
    
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    echo -e " ${BOLD}[7] ${CYAN}Simple GRE IPv4${NC}  ${GREY}Manual Script + Port Mapping${NC}"
    echo -e " ${BOLD}[8] ${RED}Delete Simple${NC}    ${GREY}Clean remove of Simple GRE${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    echo -e " ${BOLD}[9] ${CYAN}Adv. Forwarding${NC}  ${GREY}Forward via Existing Tunnel IP${NC}"
    echo -e " ${BOLD}[10]${PURPLE}Edit Forwarding${NC}  ${GREY}Edit rules from Opt 9${NC}"
    echo -e " ${BOLD}[11]${RED}Del Forwarding${NC}   ${GREY}Delete specific rule${NC}"
    echo -e " ${BOLD}[12]${RED}WIPE ALL${NC}         ${GREY}Reset ALL Simple & Advanced${NC}"
    echo -e "${GREY}──────────────────────────────────────────────────────────────${NC}"
    echo -e " ${BOLD}[13]${HI_PINK}Realm Manager${NC}    ${GREY}High Performance Relay (Rust)${NC}"
    echo -e " ${BOLD}[14]${HI_GREEN}Performance${NC}      ${GREY}High-Load tuning (10k-100k+ users)${NC}"

    echo -e " ${BOLD}[0] ${WHITE}Exit${NC}"
    
    echo ""
    echo -ne " ${WHITE}Select Option:${NC} "
    read -r choice
    
    case $choice in
        1) setup_tunnel "kharej" ;;
        2) setup_tunnel "iran" ;;
        3) remove_tunnel ;;
        4) edit_tunnel ;;
        5) rm -f "$SHORTCUT_PATH"; setup_shortcut ;;
        6) rm -f "$CACHE_V4" "$CACHE_V6" "$CACHE_V4_MISS" "$CACHE_V6_MISS"; sleep 0.5 ;;
        
        # Simple GRE
        7) setup_simple_gre ;;
        8) remove_simple_gre ;;
        
        # Advanced Forwarding
        9) setup_advanced_forwarding ;;
        10) edit_advanced_rules ;;
        11) delete_advanced_rules ;;
        12) wipe_all_gre_configs ;;
        
        # Realm
        13) run_realm_menu ;;

        # Performance / High-Load
        14) run_perf_menu ;;

        0) clear; exit 0 ;;
        *) echo "Invalid option." ;;
    esac
done
