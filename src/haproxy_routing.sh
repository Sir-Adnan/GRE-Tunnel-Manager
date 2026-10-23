# Closed routing schema v1, separate from TCP/health options. No raw directives.
gtm_routing_defaults() { H_ROUTE_MODE=tcp; H_CERT=-; H_ROUTES=-; }
gtm_routing_validate() {
    local input=$1 version mode cert routes extra rule host path target key
    local -a rules=() destinations=()
    local -A seen=()
    [[ $input != *$'\t'* && $input != *$'\n'* && $input != *$'\r'* ]] || return 1
    extra=${input//[^|]/}; ((${#extra}==3)) || return 1
    IFS='|' read -r version mode cert routes <<< "$input"
    [[ $version == 1 && $mode =~ ^(sni|http|https)$ ]] || return 1
    if [[ $mode == https ]]; then [[ $cert =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}$ ]] || return 1
    else [[ $cert == - ]] || return 1; fi
    IFS=, read -r -a destinations <<< "$R_TARGETS"
    if [[ $routes != - ]]; then
        [[ -n $routes && $routes != ,* && $routes != *, && $routes != *,,* ]] || return 1
        IFS=, read -r -a rules <<< "$routes"
        ((${#rules[@]}<=16)) || return 1
        for rule in "${rules[@]}"; do
            extra=${rule//[^~]/}; ((${#extra}==2)) || return 1
            IFS='~' read -r host path target <<< "$rule"
            [[ $host =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ && $host != *..* ]] || return 1
            [[ $path == - || ( $mode != sni && $path =~ ^/[a-zA-Z0-9/_.~-]{0,127}$ ) ]] || return 1
            gtm_uint "$target" 1 "${#destinations[@]}" || return 1
            key="$host~$path"; [[ ! ${seen[$key]+set} ]] || return 1; seen[$key]=1
        done
    fi
    H_ROUTE_MODE=$mode; H_CERT=$cert; H_ROUTES=$routes
}

gtm_haproxy_certificate() {
    local dir="$GTM_CONFIG_DIR/certificates" file
    [[ $H_ROUTE_MODE == https && $H_CERT =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}$ ]] || return 1
    file="$dir/$H_CERT.pem"
    # Root-provisioned PEM only. The HTTP process never reads or uploads keys.
    [[ -d $dir && ! -L $dir && -f $file && ! -L $file ]] &&
        [[ $(stat -c %u "$dir") == 0 && $(stat -c %a "$dir") == 700 &&
           $(stat -c %u "$file") == 0 && $(stat -c %a "$file") == 600 ]] || {
        gtm_error "Provision root-owned mode-600 PEM in mode-700 directory: $file"; return 1;
    }
    printf '%s' "$file"
}

gtm_haproxy_frontend() {
    local rule host path target index=0 cert
    local -a rules=()
    printf 'frontend entrance\n    bind %s' "$(gtm_address "$R_BIND" "$((10#$R_PORT))")"
    if [[ $H_ROUTE_MODE == https ]]; then
        # Offline preview only prints the reference. Native preflight checks PEM ownership.
        cert="$GTM_CONFIG_DIR/certificates/$H_CERT.pem"
        printf ' ssl crt %s ssl-min-ver TLSv1.2 alpn http/1.1' "$cert"
    fi
    printf '\n    maxconn %d\n' "$((10#$H_MAXCONN))"
    if [[ $H_ROUTE_MODE == sni ]]; then
        printf '    tcp-request inspect-delay 5s\n    tcp-request content accept if { req.ssl_hello_type 1 }\n'
    fi
    if [[ $H_ROUTES != - ]]; then
        IFS=, read -r -a rules <<< "$H_ROUTES"
        for rule in "${rules[@]}"; do
            ((index+=1)); IFS='~' read -r host path target <<< "$rule"
            if [[ $H_ROUTE_MODE == sni ]]; then printf '    use_backend route%d if { req.ssl_sni -i %s }\n' "$index" "$host"
            else
                printf '    use_backend route%d if { hdr(host),lower,field(1,:) -m str %s }' "$index" "$host"
                [[ $path == - ]] || printf ' { path_beg %s }' "$path"
                printf '\n'
            fi
        done
    fi
    printf '    default_backend destinations\n'
}

gtm_haproxy_route_backends() {
    local rule host path target index=0
    local -a rules=()
    [[ $H_ROUTES != - ]] || return 0
    IFS=, read -r -a rules <<< "$H_ROUTES"
    for rule in "${rules[@]}"; do
        ((index+=1)); IFS='~' read -r host path target <<< "$rule"
        printf 'backend route%d\n' "$index"
        gtm_haproxy_servers "$target" || return 1
    done
}
