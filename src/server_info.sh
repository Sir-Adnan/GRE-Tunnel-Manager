# Session-only header information. No files, services, probes or package installs.
gtm_info_text() {
    local LC_ALL=C value=$1
    # External text is display data: discard controls, escapes and non-ASCII bytes.
    value=${value//[^a-zA-Z0-9 .,:_@+\(\)\&\/-]/}
    printf '%s' "${value:0:120}"
}

gtm_info_string() {
    local key=$1 payload=$2 pattern
    # Only the API's small, unescaped string fields are accepted. Never eval JSON.
    pattern='"'"$key"'"[[:space:]]*:[[:space:]]*"([^"\\]*)"'
    [[ $payload =~ $pattern ]] || return 1
    printf '%s' "${BASH_REMATCH[1]}"
}

gtm_server_local_info() {
    local key value index iface family cidr rest address route preferred4='' preferred6='' candidate4='' candidate6=''
    GTM_HOST=$(gtm_info_text "$(hostname 2>/dev/null)")
    GTM_OS='Linux'; GTM_LOCAL4=''; GTM_LOCAL6=''
    if [[ -r /etc/os-release ]]; then
        while IFS='=' read -r key value; do
            [[ $key == PRETTY_NAME ]] || continue
            value=${value#\"}; value=${value%\"}
            GTM_OS=$(gtm_info_text "$value"); break
        done < /etc/os-release
    fi
    if command -v ip >/dev/null 2>&1; then
        while IFS= read -r route; do
            [[ $route =~ ^default[[:space:]].*dev[[:space:]]+([^[:space:]]+) ]] || continue
            preferred4=${BASH_REMATCH[1]}; break
        done < <(ip -4 route show default 2>/dev/null)
        while IFS= read -r route; do
            [[ $route =~ ^default[[:space:]].*dev[[:space:]]+([^[:space:]]+) ]] || continue
            preferred6=${BASH_REMATCH[1]}; break
        done < <(ip -6 route show default 2>/dev/null)
        while read -r index iface family cidr rest; do
            address=${cidr%/*}; iface=${iface%%@*}
            case $iface in lo|gre*|ip6gre*|sit*|docker*|veth*|br-*) continue;; esac
            if [[ $family == inet ]] && gtm_ipv4 "$address"; then
                [[ -n $candidate4 ]] || candidate4=$address
                [[ $iface != "$preferred4" || -n $GTM_LOCAL4 ]] || GTM_LOCAL4=$address
            elif [[ $family == inet6 ]] && gtm_ipv6 "$address" && [[ $rest != *tentative* && $rest != *deprecated* ]]; then
                [[ -n $candidate6 ]] || candidate6=$address
                [[ $iface != "$preferred6" || -n $GTM_LOCAL6 ]] || GTM_LOCAL6=$address
            fi
        done < <(ip -o address show scope global 2>/dev/null)
        GTM_LOCAL4=${GTM_LOCAL4:-$candidate4}; GTM_LOCAL6=${GTM_LOCAL6:-$candidate6}
    fi
}

gtm_server_lookup() {
    local payload address org country asn pattern='"success"[[:space:]]*:[[:space:]]*true([[:space:],}])'
    command -v curl >/dev/null 2>&1 || return 0
    # One best-effort HTTPS request, bounded to two seconds. Bypass HTTP proxies
    # so the address is the server's egress rather than a configured proxy's IP.
    payload=$(curl -q -fsS --noproxy '*' --proto '=https' --connect-timeout 1 --max-time 2 --max-filesize 8192 \
        'https://ipwho.is/?fields=success,ip,country,connection.org,connection.asn' 2>/dev/null) || return 0
    [[ ${#payload} -le 8192 && $payload =~ $pattern ]] || return 0
    address=$(gtm_info_string ip "$payload") || return 0
    gtm_ip "$address" || return 0
    GTM_PUBLIC_IP=$address
    org=$(gtm_info_string org "$payload") || org=''
    country=$(gtm_info_string country "$payload") || country=''
    GTM_PROVIDER=$(gtm_info_text "$org"); GTM_COUNTRY=$(gtm_info_text "$country")
    pattern='"asn"[[:space:]]*:[[:space:]]*([0-9]{1,10})([[:space:],}])'
    if [[ $payload =~ $pattern ]]; then asn=${BASH_REMATCH[1]}; GTM_ASN="AS$asn"; fi
}

gtm_server_info() {
    [[ ${GTM_SERVER_INFO_READY:-0} != 1 ]] || return 0
    GTM_SERVER_INFO_READY=1
    GTM_HOST=''; GTM_OS=''; GTM_LOCAL4=''; GTM_LOCAL6=''
    GTM_PUBLIC_IP=''; GTM_PROVIDER=''; GTM_COUNTRY=''; GTM_ASN=''
    if [[ ${GTM_DEMO:-0} == 1 ]]; then
        GTM_HOST=demo-server; GTM_OS='Ubuntu 24.04'; GTM_LOCAL4=203.0.113.10; GTM_LOCAL6=2001:db8::10
        GTM_PUBLIC_IP=$GTM_LOCAL4; GTM_PROVIDER='Example Hosting'; GTM_COUNTRY=Germany; GTM_ASN=AS64500
        return 0
    fi
    gtm_server_local_info
    if [[ -t 0 && -t 1 && ${GTM_SERVER_LOOKUP:-1} != 0 ]]; then gtm_server_lookup; fi
    return 0
}

gtm_header_address() {
    local label=$1 address=$2 style=${3:-$GTM_HIGHLIGHT}
    if ((${#label}+${#address}<=GTM_UI_WIDTH)); then
        gtm_panel_text "$label$address" "$style"
    else
        gtm_panel_text "$label" "$GTM_DIM"
        # Use the full window for a long IPv6 address before wrapping it.
        if ((${#address}<=GTM_UI_WIDTH+4)); then printf '%b%s%b\n' "$style" "$address" "$GTM_RESET"
        else gtm_panel_wrap "$address" "$style"; fi
    fi
}

gtm_server_header() {
    local host provider public4='' public6=''
    gtm_server_info
    host=${GTM_HOST:-unknown}
    if ((GTM_UI_WIDTH>=64)); then host+="  /  $GTM_OS"; fi
    gtm_panel_text "Host      $host" "$GTM_DIM"
    if [[ -n $GTM_PUBLIC_IP ]]; then
        if [[ $GTM_PUBLIC_IP == *:* ]]; then public6=$GTM_PUBLIC_IP; else public4=$GTM_PUBLIC_IP; fi
    fi
    # Addresses are never ellipsized or combined with another value on a line.
    if [[ -n $public4 ]]; then gtm_header_address 'Public v4 ' "$public4"
    else gtm_header_address 'Local v4  ' "${GTM_LOCAL4:-not detected}"; fi
    if [[ -n $GTM_LOCAL4 && -n $public4 && $GTM_LOCAL4 != "$public4" ]]; then gtm_header_address 'Local v4  ' "$GTM_LOCAL4" "$GTM_INK"; fi
    if [[ -n $public6 ]]; then gtm_header_address 'Public v6 ' "$public6"
    elif [[ -n $GTM_LOCAL6 ]]; then gtm_header_address 'Local v6  ' "$GTM_LOCAL6"; fi
    if [[ -n $GTM_LOCAL6 && -n $public6 && $GTM_LOCAL6 != "$public6" ]]; then gtm_header_address 'Local v6  ' "$GTM_LOCAL6" "$GTM_INK"; fi
    provider=${GTM_PROVIDER:-unavailable}
    [[ -z $GTM_ASN ]] || provider+=" / $GTM_ASN"
    [[ -z $GTM_COUNTRY ]] || provider+=" / $GTM_COUNTRY"
    gtm_panel_text "Provider  $provider" "$GTM_DIM"
}
