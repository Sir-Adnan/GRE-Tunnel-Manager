#!/usr/bin/env bash
# GRE Tunnel Manager installer.
#
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh)"
#   sudo bash -c "$(curl -fsSL .../install.sh)" @ --http --port 8080 --user admin --password-env PANEL_PASS --yes
#
# "curl ... | sudo bash" works too; questions are then read from /dev/tty.
#
# Downloads the prebuilt release, verifies its SHA-256 checksum and hands
# over to "gtm install", which asks a few questions (or takes the options
# below) and sets up the web panel. Run with --help for every option.
set -euo pipefail
GTM_VERSION=1.6.1
GTM_REPOSITORY=Sir-Adnan/GRE-Tunnel-Manager

gtm_say() { printf '  %s\n' "$*"; }
gtm_fail() { printf '\n  x %s\n\n' "$*" >&2; return 1; }
# Step lines in the style of the setup that follows: "›" starts, "✓" ends.
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
    gtm_step() { printf '  \033[1;94m›\033[0m %s\n' "$*"; }
    gtm_done() { printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
else
    gtm_step() { printf '  > %s\n' "$*"; }
    gtm_done() { printf '  + %s\n' "$*"; }
fi

gtm_bootstrap_help() {
    cat <<'EOF'

  GRE Tunnel Manager installer

  Usage: sudo bash install.sh [options]
         sudo bash -c "$(curl -fsSL URL)" @ [options]

  Without options it asks a few questions. With --yes it installs with
  Let's Encrypt HTTPS for the detected public IP, a random port and a
  generated password. Options answer their question; the rest are asked.

  Examples
    HTTP, own port and login, no questions:
      sudo bash install.sh --http --port 8080 --user admin \
        --password 'a-long-password' --yes
    Trusted HTTPS for a domain:
      sudo bash install.sh --domain panel.example.com --yes

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
    printf '\n'
    gtm_say "GRE Tunnel Manager v$version · installer"
    printf '\n'
    if ((${#missing[@]})); then
        [[ -z $package_dir ]] || { gtm_fail "Missing tools: ${missing[*]}"; return 1; }
        gtm_step "Installing ${missing[*]}"
        DEBIAN_FRONTEND=noninteractive apt-get update -qq </dev/null >/dev/null &&
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends curl tar coreutils gawk ca-certificates </dev/null >/dev/null ||
            { gtm_fail "Could not install ${missing[*]} with apt-get."; return 1; }
    fi
    tmp=$(mktemp -d)
    GTM_BOOTSTRAP_TMP=$tmp
    trap 'rm -rf -- "$GTM_BOOTSTRAP_TMP"' EXIT
    member="gtm-panel-v$version-linux-$arch.tar.gz"
    if [[ -n $package_dir ]]; then
        cp -- "$package_dir/$member" "$package_dir/SHA256SUMS" "$tmp/" || { gtm_fail "$member and SHA256SUMS are not in $package_dir"; return 1; }
    else
        gtm_step "Downloading the release for $arch (prebuilt; nothing is compiled)"
        local base="https://github.com/$GTM_REPOSITORY/releases/download/v$version" show=-sS
        # A progress bar on a terminal; quiet in logs and pipes.
        [[ -t 2 ]] && show=--progress-bar
        curl --proto '=https' --tlsv1.2 -fL "$show" --connect-timeout 15 --max-time 300 "$base/$member" -o "$tmp/$member" &&
            curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 15 --max-time 30 "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" ||
            { gtm_fail "Could not download v$version from GitHub. Check the network, or use --package-dir."; return 1; }
    fi
    (cd "$tmp" && awk -v name="$member" '$2 == name || $2 == "*" name {print}' SHA256SUMS > selected.sha256 &&
        [[ $(wc -l < selected.sha256) == 1 ]] && sha256sum --quiet -c selected.sha256) ||
        { gtm_fail 'Checksum verification failed; nothing was installed.'; return 1; }
    # Only the two fixed members are extracted; archive paths are never trusted.
    tar -xzf "$tmp/$member" -C "$tmp" gtm-panel gre.sh || { gtm_fail 'The release archive is damaged.'; return 1; }
    [[ $("$tmp/gtm-panel" version 2>/dev/null) == "v$version" ]] || { gtm_fail 'The package version does not match; nothing was installed.'; return 1; }
    gtm_done "Package v$version verified (SHA-256)"
    gtm_step 'Starting setup'
    local -a gtm=("$tmp/gtm-panel" gtm "$command")
    [[ $command == remove ]] || gtm+=(--source "$tmp")
    # Under "curl | bash" standard input is the script itself; questions are
    # answered on a terminal instead: the one sudo was started from when sudo
    # gave the script a terminal of its own (see gtm_bootstrap_terminal), else
    # the controlling terminal.
    local terminal
    if [[ -t 0 ]]; then
        "${gtm[@]}" "${args[@]}"
    elif terminal=$(gtm_bootstrap_terminal); then
        "${gtm[@]}" "${args[@]}" <"$terminal" >"$terminal" 2>&1
    elif { : </dev/tty; } 2>/dev/null; then
        "${gtm[@]}" "${args[@]}" </dev/tty
    else
        "${gtm[@]}" "${args[@]}"
    fi
}

# Prints /dev/pts/N, the controlling terminal of a process, from /proc.
gtm_proc_tty() {
    local stat state ppid pgrp session nr major minor
    stat=$(<"/proc/$1/stat") 2>/dev/null || return 1
    read -r state ppid pgrp session nr _ <<< "${stat##*) }"
    major=$(( (nr >> 8) & 0xfff )); minor=$(( (nr & 0xff) | ((nr >> 12) & 0xfff00) ))
    ((major >= 136 && major <= 143)) || return 1
    printf '/dev/pts/%d %d\n' "$(( (major - 136) * 256 + minor ))" "$ppid"
}

# "curl | sudo bash": sudo's use_pty (the default on current Ubuntu and
# Debian) runs the script on a new pseudo-terminal and, because its own input
# is the pipe, passes no keystrokes to it, so a question there could never be
# answered. The terminal sudo was started from still has the keyboard; this
# finds it among the next few ancestors and prints it when it differs from
# our own.
gtm_bootstrap_terminal() {
    local own pid=$PPID tty parent i
    [[ -n ${SUDO_USER:-} ]] || return 1
    read -r own _ < <(gtm_proc_tty $$) || return 1
    for ((i = 0; i < 4 && pid > 1; i++)); do
        read -r tty parent < <(gtm_proc_tty "$pid") || return 1
        if [[ $tty != "$own" && -c $tty && -r $tty && -w $tty ]]; then
            printf '%s' "$tty"
            return 0
        fi
        pid=$parent
    done
    return 1
}

gtm_bootstrap_main "$@"
