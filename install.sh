#!/usr/bin/env bash
# GRE Tunnel Manager installer.
#
#   curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh | sudo bash
#   curl -fsSL .../install.sh | sudo bash -s -- --domain panel.example.com --yes
#
# Downloads the prebuilt release, verifies its SHA-256 checksum and hands
# over to "gtm install", which asks a few questions (or takes the options
# below) and sets up the web panel. Run with --help for every option.
set -euo pipefail
GTM_VERSION=1.6.0
GTM_REPOSITORY=Sir-Adnan/GRE-Tunnel-Manager

gtm_say() { printf '  %s\n' "$*"; }
gtm_fail() { printf '\n  x %s\n\n' "$*" >&2; return 1; }

gtm_bootstrap_help() {
    cat <<'EOF'

  GRE Tunnel Manager installer

  Usage: sudo bash install.sh [options]

  Without options it asks a few questions. With --yes it installs with
  Let's Encrypt HTTPS for the detected public IP, a random port and a
  generated password.

  Panel
    --domain NAME          Domain (or IP) for the panel; default: public IP
    --port N               TCP port; default: a free random port
    --user NAME            Login name; default: admin
    --password-env VAR     Read the password from an environment variable
                           (sudo --preserve-env=VAR bash install.sh ...)
    --password VALUE       Password on the command line (visible in history)
    --https | --self-signed | --http
                           Let's Encrypt (default), self-signed or plain HTTP
    --email ADDRESS        Let's Encrypt contact (optional)
    --cloudflare-token-file FILE
                           Verify the domain over Cloudflare DNS
    --engines              Also install every tunnel engine
    --no-update-check      Skip the daily check for new releases
    --yes                  Accept defaults; ask nothing

  Other tasks
    --agent [--operations] [--traffic]   Install an outbound Agent
    --remove                             Remove the panel (tunnels stay)

  Installer
    --version X.Y.Z        Install another published release
    --package-dir DIR      Use a local archive and SHA256SUMS (offline)

  After installation, run "sudo gtm" for status, updates and maintenance.

EOF
}

gtm_bootstrap_main() {
    local version=$GTM_VERSION package_dir='' command=install arch tmp member
    local -a args=()
    while (($#)); do
        case $1 in
            --help|-h) gtm_bootstrap_help; return 0;;
            --version)
                (($# >= 2)) && [[ $2 =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { gtm_fail '--version needs a release number such as 1.6.0'; return 1; }
                version=$2; shift 2;;
            --package-dir)
                (($# >= 2)) && [[ -d $2 ]] || { gtm_fail '--package-dir needs a directory with the archive and SHA256SUMS'; return 1; }
                package_dir=$(cd -- "$2" && pwd -P); shift 2;;
            --remove|--uninstall) command=remove; shift;;
            *) args+=("$1"); shift;;
        esac
    done
    [[ $(uname -s) == Linux ]] || { gtm_fail 'GRE Tunnel Manager runs on Linux (Debian or Ubuntu with systemd).'; return 1; }
    [[ $EUID == 0 ]] || { gtm_fail 'Run as root: curl ... | sudo bash'; return 1; }
    command -v systemctl >/dev/null && command -v apt-get >/dev/null || { gtm_fail 'Debian or Ubuntu with systemd is required.'; return 1; }
    case $(uname -m) in
        x86_64) arch=amd64;;
        aarch64|arm64) arch=arm64;;
        *) gtm_fail 'Supported architectures: x86_64 and aarch64.'; return 1;;
    esac
    local tool missing=()
    for tool in curl tar sha256sum awk; do command -v "$tool" >/dev/null || missing+=("$tool"); done
    if ((${#missing[@]})); then
        [[ -z $package_dir ]] || { gtm_fail "Missing tools: ${missing[*]}"; return 1; }
        gtm_say "Installing ${missing[*]}"
        apt-get update -qq </dev/null && apt-get install -y -qq --no-install-recommends curl tar coreutils gawk ca-certificates </dev/null >/dev/null
    fi
    tmp=$(mktemp -d)
    GTM_BOOTSTRAP_TMP=$tmp
    trap 'rm -rf -- "$GTM_BOOTSTRAP_TMP"' EXIT
    member="gtm-panel-v$version-linux-$arch.tar.gz"
    printf '\n'
    gtm_say "GRE Tunnel Manager v$version"
    if [[ -n $package_dir ]]; then
        cp -- "$package_dir/$member" "$package_dir/SHA256SUMS" "$tmp/" || { gtm_fail "$member and SHA256SUMS are not in $package_dir"; return 1; }
    else
        gtm_say 'Downloading the prebuilt release (no compiler or runtime is installed)'
        local base="https://github.com/$GTM_REPOSITORY/releases/download/v$version"
        curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 15 --max-time 300 "$base/$member" -o "$tmp/$member" &&
            curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 15 --max-time 30 "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" ||
            { gtm_fail "Could not download v$version from GitHub. Check the network, or use --package-dir."; return 1; }
    fi
    (cd "$tmp" && awk -v name="$member" '$2 == name || $2 == "*" name {print}' SHA256SUMS > selected.sha256 &&
        [[ $(wc -l < selected.sha256) == 1 ]] && sha256sum --quiet -c selected.sha256) ||
        { gtm_fail 'Checksum verification failed; nothing was installed.'; return 1; }
    # Only the two fixed members are extracted; archive paths are never trusted.
    tar -xzf "$tmp/$member" -C "$tmp" gtm-panel gre.sh || { gtm_fail 'The release archive is damaged.'; return 1; }
    [[ $("$tmp/gtm-panel" version 2>/dev/null) == "v$version" ]] || { gtm_fail 'The package version does not match; nothing was installed.'; return 1; }
    gtm_say 'Package verified (SHA-256)'
    local -a gtm=("$tmp/gtm-panel" gtm "$command")
    [[ $command == remove ]] || gtm+=(--source "$tmp")
    # Under "curl | bash" standard input is the script itself; questions are
    # answered on the terminal instead.
    if [[ ! -t 0 ]] && { : </dev/tty; } 2>/dev/null; then
        "${gtm[@]}" "${args[@]}" </dev/tty
    else
        "${gtm[@]}" "${args[@]}"
    fi
}

gtm_bootstrap_main "$@"
