#!/usr/bin/env bash
# Optional prebuilt Go panel installer. Never changes tunnel configurations.
set -euo pipefail
PANEL_VERSION=1.3.0
PANEL_REPOSITORY=Sir-Adnan/GRE-Tunnel-Manager

panel_install_options() {
    PANEL_SETUP_ARGS=()
    PANEL_PACKAGE_DIR=''
    PANEL_INSTALL_ENGINES=false
    while (($#)); do
        case $1 in
            --quick) PANEL_SETUP_ARGS+=(--quick); shift;;
            --protocol|--address|--port|--listen|--username)
                (($# >= 2)) && [[ -n $2 && $2 != --* ]] || { printf 'Missing value for %s\n' "$1" >&2; return 1; }
                PANEL_SETUP_ARGS+=("$1" "$2"); shift 2;;
            --package-dir)
                (($# >= 2)) && [[ -d $2 ]] || { printf 'Provide a directory containing the matching archive and SHA256SUMS.\n' >&2; return 1; }
                PANEL_PACKAGE_DIR=$(cd -- "$2" && pwd -P); shift 2;;
            --install-engines) PANEL_INSTALL_ENGINES=true; shift;;
            --help|-h)
                printf 'Usage: sudo bash panel-install.sh [--quick] [--protocol https|http] [--address IP_OR_DOMAIN]\n  [--port PORT] [--username USER] [--listen LOCAL_IP] [--install-engines]\n  [--package-dir DIR]  Use locally built packages with SHA256SUMS.\n\nEmpty address detects the public IP. Port 0 selects an available random port.\nExisting installations keep their address, protocol, credentials and certificates.\n'
                return 2;;
            *) printf 'Unknown installer option. Run --help for supported options.\n' >&2; return 1;;
        esac
    done
}

panel_install_main() {
    local options_result=0
    panel_install_options "$@" || options_result=$?
    [[ $options_result != 2 ]] || return 0
    [[ $options_result == 0 ]] || return "$options_result"
    [[ $(uname -s) == Linux && $EUID == 0 ]] || { printf 'Run on Linux with sudo or root.\n' >&2; return 1; }
    command -v systemctl >/dev/null && command -v apt-get >/dev/null || { printf 'Debian/Ubuntu with systemd is required.\n' >&2; return 1; }
    local arch tmp component public_ip='' member account_uid account_shell group_members setup_version
    case $(uname -m) in x86_64) arch=amd64;; aarch64) arch=arm64;; *) printf 'Supported architectures: x86_64 and aarch64.\n' >&2; return 1;; esac
    if ! command -v ip >/dev/null || ! command -v flock >/dev/null; then
        printf 'Installing required system tools (iproute2/util-linux).\n'
        apt-get update && apt-get install -y --no-install-recommends iproute2 util-linux ca-certificates
    fi
    for component in curl tar sha256sum install getent useradd; do command -v "$component" >/dev/null || { printf 'Install the prerequisite: %s\n' "$component" >&2; return 1; }; done
    exec 9>/run/gre-manager-panel-install.lock
    flock -n 9 || { printf 'Another panel installation is running.\n' >&2; return 1; }
    tmp=$(mktemp -d)
    PANEL_INSTALL_TMP=$tmp
    trap 'rm -rf -- "$PANEL_INSTALL_TMP"' EXIT
    member="gtm-panel-v$PANEL_VERSION-linux-$arch.tar.gz"
    printf '\nGRE Tunnel Manager / Web Panel v%s\nDownloading a prebuilt binary; no Go or Node runtime is installed.\n' "$PANEL_VERSION"
    if [[ -n $PANEL_PACKAGE_DIR ]]; then
        cp -- "$PANEL_PACKAGE_DIR/$member" "$PANEL_PACKAGE_DIR/SHA256SUMS" "$tmp/"
    else
        curl --proto '=https' --tlsv1.2 -fL --connect-timeout 15 --max-time 180 "https://github.com/$PANEL_REPOSITORY/releases/download/v$PANEL_VERSION/$member" -o "$tmp/$member"
        curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 15 --max-time 30 "https://github.com/$PANEL_REPOSITORY/releases/download/v$PANEL_VERSION/SHA256SUMS" -o "$tmp/SHA256SUMS"
    fi
    (cd "$tmp"; awk -v name="$member" '$2 == name {print}' SHA256SUMS > selected.sha256; [[ $(wc -l < selected.sha256) == 1 ]] && sha256sum -c selected.sha256)
    # Only fixed archive members are extracted; no paths from an archive listing.
    tar -xzf "$tmp/$member" -C "$tmp" gtm-panel gre.sh
    [[ $("$tmp/gtm-panel" version) == "v$PANEL_VERSION" ]] || { printf 'Package version does not match the installer.\n' >&2; return 1; }
    bash -n "$tmp/gre.sh"
    setup_version=$("$tmp/gtm-panel" setup-version 2>/dev/null || true)
    if [[ $setup_version != 2 && ${#PANEL_SETUP_ARGS[@]} -gt 0 && ! -f /etc/gre-manager-panel/config.json ]]; then
        printf 'This published package predates quick HTTP/HTTPS setup. Use a newer matching release or --package-dir with the updated build. No services were stopped.\n' >&2
        return 1
    fi
    getent group grepanel >/dev/null || groupadd --system grepanel
    group_members=$(getent group grepanel | cut -d: -f4)
    [[ -z $group_members || $group_members == grepanel ]] || { printf 'The grepanel group has other members; inspect it before installation.\n' >&2; return 1; }
    if ! getent passwd grepanel >/dev/null; then useradd --system --gid grepanel --home-dir /nonexistent --shell /usr/sbin/nologin grepanel; fi
    account_uid=$(id -u grepanel); account_shell=$(getent passwd grepanel | cut -d: -f7)
    [[ $account_uid -gt 0 && $account_uid -lt 1000 && ( $account_shell == /usr/sbin/nologin || $account_shell == /bin/false ) ]] || { printf 'grepanel already belongs to an unrelated account; installation stopped.\n' >&2; return 1; }
    install -d -m 755 /usr/local/lib/gre-manager
    install -d -o root -g grepanel -m 750 /etc/gre-manager-panel
    install -d -o root -g root -m 700 /var/lib/gre-manager-panel
    # Complete setup before stopping a working panel. Updates never rerun setup.
    if [[ ! -f /etc/gre-manager-panel/config.json ]]; then
        if [[ $setup_version == 2 ]]; then
            "$tmp/gtm-panel" setup "${PANEL_SETUP_ARGS[@]}"
        else
            printf 'Published v%s uses the earlier HTTPS setup. Quick setup becomes available with an updated package.\n' "$PANEL_VERSION"
            read -r -p 'Public server IP (for HTTPS certificate): ' public_ip
            "$tmp/gtm-panel" setup --public-ip "$public_ip"
        fi
    else
        printf 'Existing address, protocol, port, credentials and certificates are preserved. Setup options do not override them.\n'
    fi
    # Validate existing configuration with the incoming binary before any stop.
    "$tmp/gtm-panel" address >/dev/null
    chown root:grepanel /etc/gre-manager-panel/config.json
    chmod 640 /etc/gre-manager-panel/config.json
    for component in server.key server.crt; do
        if [[ -f /etc/gre-manager-panel/$component ]]; then chown root:grepanel "/etc/gre-manager-panel/$component"; fi
    done
    [[ ! -f /etc/gre-manager-panel/server.key ]] || chmod 640 /etc/gre-manager-panel/server.key
    # Stop only panel processes while replacing its private executable/helper.
    if systemctl cat gre-manager-panel.service >/dev/null 2>&1; then systemctl stop gre-manager-panel.service gre-manager-panel-broker.service; fi
    install -m 755 "$tmp/gtm-panel" /usr/local/bin/gtm-panel
    install -m 700 "$tmp/gre.sh" /usr/local/lib/gre-manager/manager.sh
    cat > /etc/systemd/system/gre-manager-panel-broker.service <<'EOF'
[Unit]
Description=GRE Manager private control broker
After=network-online.target
StopWhenUnneeded=yes
[Service]
Type=simple
User=root
Group=grepanel
RuntimeDirectory=gre-manager-panel
RuntimeDirectoryMode=0750
UMask=0077
ExecStart=/usr/local/bin/gtm-panel broker
Restart=on-failure
RestartSec=3
TimeoutStopSec=12min
KillMode=mixed
Environment=GOMEMLIMIT=64MiB
ProtectHome=yes
PrivateTmp=yes
EOF
    cat > /etc/systemd/system/gre-manager-panel.service <<'EOF'
[Unit]
Description=GRE Tunnel Manager Web Panel
Requires=gre-manager-panel-broker.service
After=gre-manager-panel-broker.service network-online.target
[Service]
Type=simple
User=grepanel
Group=grepanel
UMask=0077
ExecStart=/usr/local/bin/gtm-panel serve
Restart=on-failure
RestartSec=3
Environment=GOMEMLIMIT=64MiB
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now gre-manager-panel.service
    sleep 1
    systemctl is-active --quiet gre-manager-panel.service || { journalctl -u gre-manager-panel -n 20 --no-pager; return 1; }
    if [[ $PANEL_INSTALL_ENGINES == true ]]; then
        /bin/bash /usr/local/lib/gre-manager/manager.sh --api install iptables nftables haproxy realm frp rathole
    else
        printf '\nInstall optional engines later from the panel or terminal menu. Use --install-engines to preinstall all.\n'
    fi
    printf '\nPanel is running. Allow its chosen TCP port in your server/provider firewall.\n'
    gtm-panel address
    printf 'Manage it with: sudo bash gre.sh --panel\n'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then panel_install_main "$@"; fi
