# Explicit engine maintenance. Never restart active tunnels during a binary update.
gtm_component_policy() {
    (($#==1)) && [[ $1 =~ ^(iptables|nftables|haproxy)$ ]] && gtm_need apt-cache || return 1
    LC_ALL=C apt-cache policy "$1"
}

# Stage every fixed binary before replacing any; keep previous binaries for recovery.
gtm_component_publish() (
    local source=$1 binary target staged backup result=0
    shift
    local -a names=("$@") published=() candidates=()
    local directory="$GTM_CONFIG_DIR/engine-backups"
    mkdir -p "$directory" && chmod 700 "$directory" || return 1
    backup=$(mktemp -d "$directory/update.XXXXXX") || return 1
    trap 'for staged in "${candidates[@]}"; do [[ ! -f $staged ]] || rm -f "$staged"; done' EXIT
    for binary in "${names[@]}"; do
        [[ $binary =~ ^(realm|frpc|frps|rathole)$ && -f $source/$binary && ! -L $source/$binary ]] || return 1
        target="/usr/local/bin/$binary"
        [[ ! -L $target && ( ! -e $target || -f $target ) ]] || return 1
        if [[ -e $target ]]; then cp -p "$target" "$backup/$binary" || return 1; fi
        staged=$(mktemp "/usr/local/bin/.gtm-engine-$binary.XXXXXX.tmp") || return 1
        candidates+=("$staged")
        install -m 755 "$source/$binary" "$staged" || return 1
        printf '%s\n' "$staged" > "$backup/$binary.staged" || return 1
    done
    for binary in "${names[@]}"; do
        IFS= read -r staged < "$backup/$binary.staged" || { result=1; break; }
        if mv -f "$staged" "/usr/local/bin/$binary"; then published+=("$binary"); else result=1; break; fi
    done
    if ((result)); then
        for binary in "${published[@]}"; do
            if [[ -f $backup/$binary ]]; then
                install -m 755 "$backup/$binary" "/usr/local/bin/$binary" || gtm_error "Partial engine recovery: restore $backup/$binary manually."
            else rm -f "/usr/local/bin/$binary" || gtm_error "Partial engine recovery: inspect /usr/local/bin/$binary."; fi
        done
        return 1
    fi
    for binary in "${names[@]}"; do rm -f "$backup/$binary.staged" || return 1; done
)

gtm_component_update() (
    set -o pipefail
    local component=$1 expected=${2:-} expected_peer=${3:-} actual binary current candidate package_version
    [[ $component =~ ^(iptables|nftables|haproxy|realm|frp|rathole)$ ]] && gtm_prepare && gtm_lock || return 1
    trap gtm_unlock EXIT
    case $component in
        iptables|nftables|haproxy)
            [[ $expected =~ ^[a-f0-9]{64}$ ]] || return 1
            actual=$(gtm_component_policy "$component" | sha256sum); actual=${actual%% *}
            [[ $actual == "$expected" ]] || { gtm_error 'Package metadata changed; check versions again.'; return 1; }
            candidate=$(gtm_component_policy "$component" | awk '$1 == "Candidate:" {print $2; exit}')
            [[ $candidate =~ ^[a-zA-Z0-9.+:~_-]+$ && $candidate != '(none)' ]] || return 1
            gtm_need dpkg && gtm_need dpkg-query || return 1
            package_version=$(dpkg-query -W -f='${Version}' "$component") && dpkg --compare-versions "$candidate" gt "$package_version" || { gtm_error 'No newer installed-package candidate is available.'; return 1; }
            # Respect existing package policy; use a no-start policy when absent.
            # No repositories, upstream PPAs or host firewall policies are added.
            GTM_PACKAGE_REFRESH=0 gtm_install_packages --only-upgrade "$component=$candidate";;
        *)
            binary=$component; [[ $component != frp ]] || binary=frpc
            current=$(command -v "$binary") || return 1
            [[ $current == "/usr/local/bin/$binary" ]] || { gtm_error 'This binary is externally managed; update it using its original installer.'; return 1; }
            [[ $expected =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}([-+~][a-zA-Z0-9.+~_-]{1,40})?$ ]] || return 1
            actual=$("$current" --version) || return 1
            if [[ $component == rathole && $actual == *'Build Version:'* ]]; then actual=$(awk '$1 == "Build" && $2 == "Version:" {print $3; exit}' <<< "$actual")
            elif [[ $actual =~ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}([-+~][a-zA-Z0-9.+~_-]{1,40})?) ]]; then actual=${BASH_REMATCH[1]}; fi
            [[ $actual == "$expected" ]] || { gtm_error 'Engine changed; check versions again.'; return 1; }
            if [[ $component == frp ]]; then
                [[ $(command -v frps) == /usr/local/bin/frps && $expected_peer =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
                actual=$(/usr/local/bin/frps --version) && [[ $actual == "$expected_peer" ]] || { gtm_error 'FRP server binary changed; check versions again.'; return 1; }
            fi
            gtm_confirm() { return 0; }
            gtm_install_component "$component" update;;
    esac
)
