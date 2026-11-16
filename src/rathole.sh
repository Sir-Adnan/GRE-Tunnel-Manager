# Optional reverse connections. This preset always uses authenticated Noise NK.
# RATH_* settings are validated data; configurations are never sourced.
gtm_rathole_key() { [[ $1 =~ ^[a-zA-Z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]]; }

gtm_rathole_binary() {
    local version
    command -v rathole >/dev/null 2>&1 || return 1
    version=$(rathole --version 2>/dev/null) || return 1
    # Official 0.5.0 archives print a multiline build report, whereas local
    # builds can use clap's short version line.
    if [[ $version == rathole* && $(awk '$1 == "Build" && $2 == "Version:" {print $3; exit}' <<< "$version") == 0.5.0 ]]; then return 0; fi
    [[ $version == 'rathole 0.5.0' || $version == 'rathole v0.5.0' ]] || {
        gtm_error 'This adapter is tested with rathole 0.5.0. Existing binaries are kept.'; return 1;
    }
}

gtm_rathole_download() {
    local archive sha tmp
    gtm_need curl && gtm_need unzip && gtm_need sha256sum && gtm_need install || return 1
    case $(uname -m) in
        x86_64) archive=rathole-x86_64-unknown-linux-gnu.zip; sha=3e7d0d0f365120cd3cd351d147d1a12ee960c8068b464d4dd533a3821873b80e ;;
        aarch64) archive=rathole-aarch64-unknown-linux-musl.zip; sha=fa4a6fc63d86f8f1faa7c103a845e4715ce79a048455c0eec897b27237576564 ;;
        *) gtm_error 'The rathole installer supports x86_64 and aarch64 Linux.'; return 1 ;;
    esac
    tmp=$(mktemp -d "$GTM_RUN_DIR/rathole-download.XXXXXX") || return 1
    if ! { curl --proto '=https' --tlsv1.2 -fL --connect-timeout 15 --max-time 180 "https://github.com/rathole-org/rathole/releases/download/v0.5.0/$archive" -o "$tmp/archive.zip" &&
        printf '%s  %s\n' "$sha" "$tmp/archive.zip" | sha256sum -c - &&
        unzip -p "$tmp/archive.zip" rathole > "$tmp/rathole" && chmod 700 "$tmp/rathole" &&
        "$tmp/rathole" --version >/dev/null && gtm_component_publish "$tmp" rathole; }; then
        rm -rf "$tmp"; return 1
    fi
    rm -rf "$tmp"
    gtm_rathole_binary
}

gtm_rathole_validate() {
    [[ $RATH_ROLE =~ ^(entrance|destination)$ && $RATH_NAME =~ ^[a-zA-Z0-9_-]{1,32}$ && $RATH_PROTO =~ ^(tcp|udp|both)$ ]] || return 1
    gtm_ip "$RATH_HOST" && gtm_ip "$RATH_LOCAL_IP" && gtm_port "$RATH_CONTROL" && gtm_port "$RATH_PUBLIC" && gtm_port "$RATH_LOCAL_PORT" || return 1
    ((10#$RATH_CONTROL != 10#$RATH_PUBLIC)) || return 1
    [[ $RATH_TOKEN =~ ^[a-zA-Z0-9_-]{24,128}$ ]] && gtm_rathole_key "$RATH_KEY" || return 1
    if [[ $RATH_ROLE == destination ]]; then
        # Reject client loops back into the remote control or public listener.
        if [[ $(gtm_ip_key "$RATH_HOST") == "$(gtm_ip_key "$RATH_LOCAL_IP")" ]]; then
            ((10#$RATH_LOCAL_PORT != 10#$RATH_CONTROL && 10#$RATH_LOCAL_PORT != 10#$RATH_PUBLIC)) || return 1
        fi
    fi
}

gtm_rathole_render() {
    gtm_rathole_validate || return 1
    local role=client proto
    local -a protocols=("$RATH_PROTO")
    [[ $RATH_PROTO != both ]] || protocols=(tcp udp)
    [[ $RATH_ROLE != entrance ]] || role=server
    printf '[%s]\n' "$role"
    if [[ $role == server ]]; then printf 'bind_addr = "%s"\n' "$(gtm_address "$RATH_HOST" "$((10#$RATH_CONTROL))")"
    else printf 'remote_addr = "%s"\nretry_interval = 3\n' "$(gtm_address "$RATH_HOST" "$((10#$RATH_CONTROL))")"; fi
    printf '\n[%s.transport]\ntype = "noise"\n\n[%s.transport.tcp]\nnodelay = true\nkeepalive_secs = 20\nkeepalive_interval = 8\n' "$role" "$role"
    printf '\n[%s.transport.noise]\npattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"\n' "$role"
    if [[ $role == server ]]; then printf 'local_private_key = "%s"\n' "$RATH_KEY"
    else printf 'remote_public_key = "%s"\n' "$RATH_KEY"; fi
    for proto in "${protocols[@]}"; do
        printf '\n[%s.services."%s_%s"]\ntype = "%s"\ntoken = "%s"\n' "$role" "$RATH_NAME" "$proto" "$proto" "$RATH_TOKEN"
        if [[ $role == server ]]; then printf 'bind_addr = "%s"\n' "$(gtm_address "$RATH_HOST" "$((10#$RATH_PUBLIC))")"
        else printf 'local_addr = "%s"\n' "$(gtm_address "$RATH_LOCAL_IP" "$((10#$RATH_LOCAL_PORT))")"; fi
    done
}

gtm_rathole_unit() {
    local bin=$1 config=$2
    cat <<EOF
[Unit]
Description=Traffic Manager rathole reverse connection
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
ExecStart=$bin $config
Environment=RUST_LOG=warn
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

# The shared lock is held by the caller. Existing instances are never overwritten.
gtm_rathole_create() {
    local id="gtm-rathole-$RATH_ROLE-$RATH_NAME" config unit tmp bin
    config="$GTM_CONFIG_DIR/$id.toml"; unit="$GTM_SERVICE_DIR/$id.service"
    [[ ! -e $config && ! -L $config && ! -e $unit && ! -L $unit ]] || { gtm_error 'Name already exists. Choose another name or remove that instance.'; return 1; }
    gtm_rathole_validate && gtm_rathole_binary || return 1
    if [[ $RATH_ROLE == entrance ]]; then
        gtm_local_address "$RATH_HOST" && gtm_port_available tcp "$RATH_HOST" "$RATH_CONTROL" &&
            gtm_port_available "$RATH_PROTO" "$RATH_HOST" "$RATH_PUBLIC" || return 1
    fi
    tmp=$(mktemp "$GTM_RUN_DIR/rathole-config.XXXXXX") || return 1
    bin=$(command -v rathole)
    if ! { gtm_rathole_render > "$tmp" && chmod 600 "$tmp" && mv "$tmp" "$config" && gtm_rathole_unit "$bin" "$config" > "$unit" &&
        systemctl daemon-reload && systemctl enable --now "$id"; }; then
        rm -f "$tmp"
        gtm_rathole_cleanup "$id" || return 1
        return 1
    fi
    sleep 1
    if ! systemctl is-active --quiet "$id"; then
        journalctl -u "$id" -n 15 --no-pager
        gtm_rathole_cleanup "$id" || return 1
        return 1
    fi
    printf 'Created %s. A running process does not prove the peer is connected.\n' "$id"
}

gtm_rathole_cleanup() {
    local id=$1
    [[ $id =~ ^gtm-rathole-(entrance|destination)-[a-zA-Z0-9_-]{1,32}$ ]] || return 1
    systemctl disable --now "$id" || { gtm_error 'Could not stop service. Config and unit were kept for recovery.'; return 1; }
    rm -f "$GTM_SERVICE_DIR/$id.service" "$GTM_CONFIG_DIR/$id.toml" || return 1
    systemctl daemon-reload
}
