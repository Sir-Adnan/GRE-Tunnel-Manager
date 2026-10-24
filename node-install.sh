#!/usr/bin/env bash
# Optional Controller or outbound Agent. Writes require explicit --operations.
set -euo pipefail
NODE_VERSION=1.3.2
NODE_REPOSITORY=Sir-Adnan/GRE-Tunnel-Manager

node_install_main() {
    local role='' address='' listen='0.0.0.0:9443' package_dir='' arch tmp member item uid shell members operations=0 traffic=0
    while (($#)); do
        case $1 in
            --operations) operations=1; shift;;
            --traffic) traffic=1; shift;;
            --controller|--agent) [[ -z $role ]] || { printf 'Choose one role.\n' >&2; return 1; }; role=${1#--}; shift;;
            --url|--listen|--package-dir)
                (($# >= 2)) && [[ -n $2 && $2 != --* ]] || { printf 'Missing option value.\n' >&2; return 1; }
                case $1 in --url) address=$2;; --listen) listen=$2;; --package-dir) package_dir=$(cd -- "$2" && pwd -P);; esac
                shift 2;;
            --help|-h)
                printf 'Usage:\n  sudo bash node-install.sh --controller --url https://IP_OR_DOMAIN:9443 [--listen 0.0.0.0:9443]\n  sudo bash node-install.sh --agent [--operations] [--traffic] [--package-dir DIR]\n\nAgent is read-only by default. --operations enables leased GRE/FRP creation.\n--traffic allows optional local accounting and read-only summaries; enable collection separately with sudo gtm-panel nodes traffic --enable.\nController requires an updated installed panel. Agent prompts for a hidden one-time code.\nNo password, invitation or private key is accepted as a command argument.\n'
                return 0;;
            *) printf 'Unknown option. Run --help.\n' >&2; return 1;;
        esac
    done
    [[ $(uname -s) == Linux && $EUID == 0 && -n $role ]] || { printf 'Choose --controller or --agent and run as Linux root.\n' >&2; return 1; }
    for item in systemctl apt-get flock install getent useradd groupadd runuser; do command -v "$item" >/dev/null || { printf 'Missing prerequisite: %s\n' "$item" >&2; return 1; }; done
    exec 9>/run/gre-manager-panel-install.lock
    flock -n 9 || { printf 'Another panel/agent installation is running.\n' >&2; return 1; }
    if [[ $role == controller ]]; then
        ((operations==0 && traffic==0)) || { printf '--operations and --traffic are Agent options.\n' >&2; return 1; }
        [[ -z $package_dir && -f /etc/gre-manager-panel/config.json && -n $address ]] || { printf 'Install the updated panel first; provide --url for the dedicated Agent HTTPS listener.\n' >&2; return 1; }
        [[ $(/usr/local/bin/gtm-panel nodes protocol 2>/dev/null) == 1 ]] || { printf 'Installed panel lacks Node protocol 1. Use a current source package.\n' >&2; return 1; }
        # Validate the reserved service account before assigning signing-key access.
        uid=$(id -u grepanel); shell=$(getent passwd grepanel | cut -d: -f7)
        [[ $uid -gt 0 && $uid -lt 1000 && ( $shell == /usr/sbin/nologin || $shell == /bin/false ) ]] || { printf 'Inspect the grepanel account first.\n' >&2; return 1; }
        install -d -o grepanel -g grepanel -m 700 /var/lib/gre-manager-nodes
        if [[ ! -f /var/lib/gre-manager-nodes/controller.json ]]; then
            runuser -u grepanel -- /usr/local/bin/gtm-panel nodes init --url "$address" --listen "$listen"
        else
            printf 'Existing Controller identity, endpoint and enrolled nodes are preserved.\n'
        fi
        runuser -u grepanel -- /usr/local/bin/gtm-panel nodes check-controller
        install -d -m 755 /etc/systemd/system/gre-manager-panel.service.d
        printf '[Service]\nReadWritePaths=/var/lib/gre-manager-nodes\n' > /etc/systemd/system/gre-manager-panel.service.d/nodes.conf
        systemctl daemon-reload
        systemctl restart gre-manager-panel.service
        systemctl is-active --quiet gre-manager-panel.service
        printf 'Controller enabled. Open its control TCP port in the provider/host firewall. Add nodes from the panel; local management needs no Agent.\n'
        return 0
    fi
    [[ -z $address && $listen == '0.0.0.0:9443' ]] || { printf '--url and --listen are Controller options.\n' >&2; return 1; }
    if systemctl cat gre-manager-panel.service >/dev/null 2>&1; then
        printf 'This host already runs the panel and appears as its local Node; no Agent is needed.\n' >&2
        return 1
    fi
    case $(uname -m) in x86_64) arch=amd64;; aarch64) arch=arm64;; *) printf 'Supported architectures: x86_64 and aarch64.\n' >&2; return 1;; esac
    for item in curl tar sha256sum ip; do command -v "$item" >/dev/null || { printf 'Install prerequisite: %s\n' "$item" >&2; return 1; }; done
    tmp=$(mktemp -d)
    NODE_INSTALL_TMP=$tmp
    trap 'rm -rf -- "$NODE_INSTALL_TMP"' EXIT
    member="gtm-panel-v$NODE_VERSION-linux-$arch.tar.gz"
    if [[ -n $package_dir ]]; then
        cp -- "$package_dir/$member" "$package_dir/SHA256SUMS" "$tmp/"
    else
        curl --proto '=https' --tlsv1.2 -fL --connect-timeout 15 --max-time 180 "https://github.com/$NODE_REPOSITORY/releases/download/v$NODE_VERSION/$member" -o "$tmp/$member"
        curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 15 --max-time 30 "https://github.com/$NODE_REPOSITORY/releases/download/v$NODE_VERSION/SHA256SUMS" -o "$tmp/SHA256SUMS"
    fi
    (cd "$tmp"; awk -v name="$member" '$2 == name {print}' SHA256SUMS > selected.sha256; [[ $(wc -l < selected.sha256) == 1 ]] && sha256sum -c selected.sha256)
    tar -xzf "$tmp/$member" -C "$tmp" gtm-panel gre.sh
    [[ $("$tmp/gtm-panel" version) == "v$NODE_VERSION" && $("$tmp/gtm-panel" nodes protocol 2>/dev/null) == 1 ]] || { printf 'Package lacks Node protocol 1. Install a matching v1.3.2 Node package.\n' >&2; return 1; }
    bash -n "$tmp/gre.sh"
    # Preserve an existing explicit opt-in across upgrades. Do not silently
    # remove the root recovery worker while it may own an unconfirmed lease.
    if [[ -f /etc/systemd/system/gre-manager-agent.service ]]; then
        if grep -Eq '^ExecStart=/usr/local/bin/gtm-panel nodes agent( --(operations|traffic))* --operations( --(operations|traffic))*$' /etc/systemd/system/gre-manager-agent.service; then operations=1; fi
        if grep -Eq '^ExecStart=/usr/local/bin/gtm-panel nodes agent( --(operations|traffic))* --traffic( --(operations|traffic))*$' /etc/systemd/system/gre-manager-agent.service; then traffic=1; fi
    fi
    if ((operations)); then
        [[ $("$tmp/gtm-panel" nodes operations-version 2>/dev/null) == 1 ]] || { printf 'Package lacks paired operation support. Use a current source build.\n' >&2; return 1; }
    fi
    if ((traffic)); then
        [[ $("$tmp/gtm-panel" nodes traffic-version 2>/dev/null) == 1 ]] || { printf 'Package lacks traffic summary protocol 1. Use a matching source build.\n' >&2; return 1; }
    fi
    getent group greagent >/dev/null || groupadd --system greagent
    members=$(getent group greagent | cut -d: -f4)
    [[ -z $members || $members == greagent ]] || { printf 'The greagent group has unrelated members.\n' >&2; return 1; }
    getent passwd greagent >/dev/null || useradd --system --gid greagent --home-dir /nonexistent --shell /usr/sbin/nologin greagent
    uid=$(id -u greagent); shell=$(getent passwd greagent | cut -d: -f7)
    [[ $uid -gt 0 && $uid -lt 1000 && ( $shell == /usr/sbin/nologin || $shell == /bin/false ) ]] || { printf 'Inspect the existing greagent account first.\n' >&2; return 1; }
    install -d -o greagent -g greagent -m 700 /var/lib/gre-manager-agent
    # Allow the service user to execute the verified temporary binary. It is
    # public release content; this directory contains no enrollment secrets.
    chmod 711 "$tmp"
    if [[ ! -f /var/lib/gre-manager-agent/identity.json ]]; then
        # The binary reads the invitation directly from the TTY with echo disabled.
        runuser -u greagent -- "$tmp/gtm-panel" nodes enroll
    fi
    runuser -u greagent -- "$tmp/gtm-panel" nodes check
    if systemctl cat gre-manager-agent.service >/dev/null 2>&1; then systemctl stop gre-manager-agent.service gre-manager-agent-broker.service; fi
    install -d -m 755 /usr/local/lib/gre-manager
    install -m 755 "$tmp/gtm-panel" /usr/local/bin/gtm-panel
    install -m 700 "$tmp/gre.sh" /usr/local/lib/gre-manager/manager.sh
    cat > /etc/systemd/system/gre-manager-agent-broker.service <<'EOF'
[Unit]
Description=GRE Manager local read-only Agent broker
After=network-online.target
StopWhenUnneeded=yes
[Service]
User=root
Group=greagent
RuntimeDirectory=gre-manager-agent
RuntimeDirectoryMode=0750
UMask=0077
ExecStart=/usr/local/bin/gtm-panel broker --read-only --socket /run/gre-manager-agent/broker.sock
Restart=on-failure
RestartSec=5
Environment=GOMEMLIMIT=64MiB
ProtectHome=yes
PrivateTmp=yes
EOF
    cat > /etc/systemd/system/gre-manager-agent.service <<'EOF'
[Unit]
Description=GRE Manager outbound inventory Agent
Requires=gre-manager-agent-broker.service
After=gre-manager-agent-broker.service network-online.target
[Service]
User=greagent
Group=greagent
UMask=0077
ExecStart=/usr/local/bin/gtm-panel nodes agent
Restart=on-failure
RestartSec=30
RestartPreventExitStatus=1
Environment=GOMEMLIMIT=64MiB
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/gre-manager-agent
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
[Install]
WantedBy=multi-user.target
EOF
    if ((operations)); then
        sed -i 's/^StopWhenUnneeded=yes$/StopWhenUnneeded=no/; s/broker --read-only --socket/broker --read-only --node-operations --socket/' /etc/systemd/system/gre-manager-agent-broker.service
        printf 'TimeoutStopSec=12min\n' >> /etc/systemd/system/gre-manager-agent-broker.service
        printf '\n[Install]\nWantedBy=multi-user.target\n' >> /etc/systemd/system/gre-manager-agent-broker.service
        sed -i 's|^ExecStart=/usr/local/bin/gtm-panel nodes agent$|ExecStart=/usr/local/bin/gtm-panel nodes agent --operations|' /etc/systemd/system/gre-manager-agent.service
    fi
    if ((traffic)); then
        install -d -o root -g root -m 700 /var/lib/gre-manager-agent-traffic
        sed -i 's/ --socket / --agent-traffic --socket /' /etc/systemd/system/gre-manager-agent-broker.service
        sed -i '/^ExecStart=.* nodes agent/s/$/ --traffic/' /etc/systemd/system/gre-manager-agent.service
    fi
    systemctl daemon-reload
    if ((operations)); then systemctl enable --now gre-manager-agent-broker.service; fi
    systemctl enable --now gre-manager-agent.service
    systemctl is-active --quiet gre-manager-agent.service
    if ((operations)); then printf 'Agent installed with paired GRE/FRP operations. Root lease recovery stays enabled independently of the Agent.\n'
    else printf 'Read-only Agent installed. No public listener, engine installation or tunnel changes.\n'; fi
    printf 'Check status: systemctl status gre-manager-agent\n'
    if ((traffic)); then printf 'Traffic reporting is available. Saved collection settings are preserved; fresh collection starts disabled.\nEnable: sudo gtm-panel nodes traffic --enable --interval 60\nPause: sudo gtm-panel nodes traffic --disable\n'; fi
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then node_install_main "$@"; fi
