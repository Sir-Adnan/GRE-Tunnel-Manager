# Optional, explicitly selected services. The manager itself is not resident.
gtm_install_component() {
    local component=$1 arch archive url sha tmp member
    case $component in
        iptables) command -v iptables >/dev/null 2>&1 && return 0 ;;
        nftables) command -v nft >/dev/null 2>&1 && return 0 ;;
        haproxy) command -v haproxy >/dev/null 2>&1 && command -v socat >/dev/null 2>&1 && return 0 ;;
        realm)
            if command -v realm >/dev/null 2>&1; then
                local installed_version
                installed_version=$(realm --version 2>/dev/null) || { gtm_error 'The installed realm command is not a supported network relay. No binary was replaced.'; return 1; }
                [[ $installed_version =~ ^realm[[:space:]]+2\. ]] || { gtm_error 'Expected Realm relay 2.x; check the existing realm command before continuing.'; return 1; }
                return 0
            fi ;;
        frp) command -v frpc >/dev/null 2>&1 && command -v frps >/dev/null 2>&1 && return 0 ;;
        rathole) if command -v rathole >/dev/null 2>&1; then gtm_rathole_binary; return $?; fi ;;
        *) return 1 ;;
    esac
    gtm_root || return 1
    printf '\nInstall optional component: %s\n' "$component"
    gtm_confirm || return 1
    if [[ $component == rathole ]]; then gtm_rathole_download; return $?; fi
    case $component in
        iptables|nftables|haproxy)
            gtm_need apt-get || return 1
            local -a packages=("$component")
            [[ $component != haproxy ]] || packages+=(socat)
            apt-get update && apt-get install -y "${packages[@]}" || return 1
            # HAProxy uses per-connection units, not the distribution's default unit.
            return 0 ;;
    esac
    gtm_need curl && gtm_need tar && gtm_need sha256sum && gtm_need install || return 1
    arch=$(uname -m)
    case $component:$arch in
        realm:x86_64) archive=realm-x86_64-unknown-linux-musl.tar.gz; sha=b1cc335547bea8bb2a88178bef12ec7f2363e36200e7ea1d4e1e67627929bf65 ;;
        realm:aarch64) archive=realm-aarch64-unknown-linux-musl.tar.gz; sha=f4c0318dd86854da483dcb7645b4f39cae2cc3f91c688fef969d53220b949488 ;;
        frp:x86_64) archive=frp_0.71.1_linux_amd64.tar.gz; sha=1d9875210972a5d1a62b2dc4c48df45ab0af05d3ca1b5e494a014428259df803 ;;
        frp:aarch64) archive=frp_0.71.1_linux_arm64.tar.gz; sha=8edf590b0c396fa42f9c147121a76af83cfc2002b08f5aef0ea1008c43482019 ;;
        *) gtm_error "Unsupported binary architecture: $arch"; return 1 ;;
    esac
    if [[ $component == realm ]]; then url="https://github.com/zhboner/realm/releases/download/v2.9.6/$archive"
    else url="https://github.com/fatedier/frp/releases/download/v0.71.1/$archive"; fi
    tmp=$(mktemp -d "$GTM_RUN_DIR/download.XXXXXX") || return 1
    if ! curl --proto '=https' --tlsv1.2 -fL --connect-timeout 15 --max-time 180 "$url" -o "$tmp/archive.tar.gz"; then rm -rf "$tmp"; return 1; fi
    if ! printf '%s  %s\n' "$sha" "$tmp/archive.tar.gz" | sha256sum -c -; then rm -rf "$tmp"; return 1; fi
    tar -xzf "$tmp/archive.tar.gz" -C "$tmp" || { rm -rf "$tmp"; return 1; }
    if [[ $component == realm ]]; then
        install -m 755 "$tmp/realm" /usr/local/bin/realm || { rm -rf "$tmp"; return 1; }
    else
        member=${archive%.tar.gz}
        install -m 755 "$tmp/$member/frpc" /usr/local/bin/frpc && install -m 755 "$tmp/$member/frps" /usr/local/bin/frps || { rm -rf "$tmp"; return 1; }
    fi
    rm -rf "$tmp"
}

gtm_realm_render() {
    local target remote index=0 weights='' algorithm=roundrobin
    local -a targets
    IFS=, read -r -a targets <<< "$R_TARGETS"
    [[ $R_STRATEGY == source ]] && algorithm=iphash
    printf '[log]\nlevel = "warn"\noutput = "stdout"\n\n[network]\nno_tcp = %s\nuse_udp = %s\n' "$([[ $R_PROTO == udp ]] && echo true || echo false)" "$([[ $R_PROTO == tcp ]] && echo false || echo true)"
    printf 'tcp_timeout = 5\nudp_timeout = 30\ntcp_keepalive = 15\n\n[[endpoints]]\nlisten = "%s"\n' "$(gtm_address "$R_BIND" "$((10#$R_PORT))")"
    for target in "${targets[@]}"; do
        gtm_endpoint "$target" || return 1; remote=$(gtm_address "$EP_IP" "$EP_PORT")
        if (( index == 0 )); then printf 'remote = "%s"\n' "$remote"
        else (( index == 1 )) && printf 'extra_remotes = ['; (( index > 1 )) && printf ', '; printf '"%s"' "$remote"; fi
        weights+="${weights:+, }$EP_WEIGHT"; ((index+=1))
    done
    if (( index > 1 )); then printf ']\nbalance = "%s: %s"\n' "$algorithm" "$weights"; fi
}

gtm_relay_unit() {
    local bin=$1 config=$2 id=$3
    cat <<EOF
[Unit]
Description=Traffic Manager $id
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
ExecStart=$bin -c $config
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
PrivateTmp=yes
RestrictSUIDSGID=yes
[Install]
WantedBy=multi-user.target
EOF
}

gtm_relays_apply() {
    local line config unit bin old file changed=0 result=0 unit_tmp previous action
    local -A wanted=()
    mkdir -p "$GTM_CONFIG_DIR/generated" || return 1
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        [[ $R_ENABLED == 1 && ( $R_ENGINE == realm || $R_ENGINE == haproxy ) ]] || continue
        gtm_need "$R_ENGINE" || return 1
        wanted[$R_ID]=1
        config="$GTM_CONFIG_DIR/generated/$R_ID.conf"; unit="$GTM_SERVICE_DIR/gtm-$R_ID.service"
        file=$(mktemp "$GTM_RUN_DIR/relay.XXXXXX") || return 1
        if [[ $R_ENGINE == haproxy ]]; then
            mkdir -p "$GTM_RUN_DIR/haproxy" && chmod 700 "$GTM_RUN_DIR/haproxy" || { rm -f "$file"; return 1; }
            gtm_haproxy_render > "$file" && haproxy -c -f "$file" || { rm -f "$file"; return 1; }
        else gtm_realm_render > "$file" || { rm -f "$file"; return 1; }; fi
        bin=$(command -v "$R_ENGINE")
        unit_tmp=$(mktemp "$GTM_RUN_DIR/unit.XXXXXX") || { rm -f "$file"; return 1; }
        if [[ $R_ENGINE == haproxy ]]; then
            gtm_haproxy_unit "$bin" "$config" "$R_ID" > "$unit_tmp" || { rm -f "$file" "$unit_tmp"; return 1; }
        else gtm_relay_unit "$bin" "$config" "$R_ID" > "$unit_tmp" || { rm -f "$file" "$unit_tmp"; return 1; }; fi
        action=restart; previous=''
        if cmp -s "$unit_tmp" "$unit" && systemctl is-active --quiet "gtm-$R_ID"; then
            if cmp -s "$file" "$config"; then rm -f "$file" "$unit_tmp"; continue; fi
            if [[ $R_ENGINE == haproxy ]]; then previous=$(gtm_haproxy_pid "$R_ID" 2>/dev/null) || previous=''; [[ -z $previous ]] || action=reload; fi
        fi
        chmod 600 "$file" "$unit_tmp" && mv "$file" "$config" && mv "$unit_tmp" "$unit" || { rm -f "$file" "$unit_tmp"; return 1; }
        systemctl daemon-reload && systemctl enable "gtm-$R_ID" && systemctl "$action" "gtm-$R_ID" || return 1
        if [[ $R_ENGINE == haproxy ]]; then gtm_haproxy_wait "$R_ID" "$previous" || return 1
        else sleep 1; fi
        systemctl is-active --quiet "gtm-$R_ID" || { journalctl -u "gtm-$R_ID" -n 15 --no-pager; return 1; }
    done
    # Stop only names from our closed ID namespace. FRP has a separate namespace.
    for old in "$GTM_SERVICE_DIR"/gtm-F??????.service; do
        [[ -f $old ]] || continue
        old=${old##*/}; old=${old#gtm-}; old=${old%.service}
        gtm_id "$old" || continue
        [[ ${wanted[$old]+set} ]] && continue
        systemctl disable --now "gtm-$old" || return 1
        rm -f "$GTM_SERVICE_DIR/gtm-$old.service" "$GTM_CONFIG_DIR/generated/$old.conf" || return 1
        rm -f "$GTM_RUN_DIR/haproxy/$old.sock" || return 1
        changed=1
    done
    (( changed == 0 )) || systemctl daemon-reload || return 1
    return "$result"
}
