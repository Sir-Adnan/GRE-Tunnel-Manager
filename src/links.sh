# Noninteractive GRE operations preserve keyed v13.7+ wire defaults.
gtm_link_create() {
    local tid=$1 role=$2 remote=$3 bind=$4 mtu=$5 family=4 maximum=1472 suffix=1 peer=2 iface unit tmp
    gtm_uint "$tid" 1 250 && [[ $role == kharej || $role == iran ]] && gtm_ip "$remote" && gtm_ip "$bind" || return 1
    tid=$((10#$tid))
    if [[ $remote == *:* ]]; then family=6; maximum=1452; [[ $bind == *:* ]] || return 1
    else [[ $bind != *:* ]] || return 1; fi
    gtm_uint "$mtu" 1280 "$maximum" && gtm_local_address "$bind" || return 1
    mtu=$((10#$mtu)); iface="gre$tid"
    if [[ $role == iran ]]; then suffix=2; peer=1; iface="gre-out-$tid"; fi
    unit="$GTM_SERVICE_DIR/gre-tun-$tid.service"
    [[ ! -e $unit && ! -L $unit ]] && ! ip link show "$iface" >/dev/null 2>&1 || { gtm_error 'GRE ID already exists.'; return 1; }
    gtm_need ip && gtm_need systemctl || return 1
    tmp=$(mktemp "$GTM_RUN_DIR/gre-unit.XXXXXX") || return 1
    {
        printf '# GTM managed GRE v1\n[Unit]\nDescription=GRE Tunnel %s\nWants=network-online.target\nAfter=network-online.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\n' "$iface"
        if ((family==6)); then
            printf 'ExecStart=/sbin/ip -6 tunnel add %s mode ip6gre remote %s local %s hoplimit 255 key %d\n' "$iface" "$remote" "$bind" "$tid"
        else printf 'ExecStart=/sbin/ip tunnel add %s mode gre remote %s local %s ttl 255 key %d\n' "$iface" "$remote" "$bind" "$tid"; fi
        printf 'ExecStart=/sbin/ip link set dev %s mtu %d\nExecStart=/sbin/ip link set dev %s up\n' "$iface" "$mtu" "$iface"
        printf 'ExecStart=/sbin/ip addr add 10.0.%d.%d/30 dev %s\nExecStart=/sbin/ip -6 addr add fd00:%d::%d/64 dev %s\n' "$tid" "$suffix" "$iface" "$tid" "$suffix" "$iface"
        printf 'ExecStop=/sbin/ip link del dev %s\nExecStopPost=-/sbin/ip link del dev %s\n[Install]\nWantedBy=multi-user.target\n' "$iface" "$iface"
    } > "$tmp"
    chmod 644 "$tmp" && mv "$tmp" "$unit" || { rm -f "$tmp"; return 1; }
    if ! { systemctl daemon-reload && systemctl enable --now "gre-tun-$tid"; }; then
        systemctl disable --now "gre-tun-$tid" || { gtm_error 'GRE startup failed and cleanup needs attention; unit kept.'; return 1; }
        rm -f "$unit"; systemctl daemon-reload; return 1
    fi
    printf 'GRE %d configured. Peer: 10.0.%d.%d. Allow protocol 47 on both servers.\n' "$tid" "$tid" "$peer"
}

gtm_link_delete() {
    local tid=$1
    gtm_uint "$tid" 1 250 || return 1
    tid=$((10#$tid))
    [[ -f $GTM_SERVICE_DIR/gre-tun-$tid.service ]] && gtm_link_remove_guard "$tid" || return 1
    # Only known manager units; custom ExecStart commands are never executed here.
    gtm_owned_gre "$tid" || { gtm_error 'Unrecognized GRE unit; inspect it manually.'; return 1; }
    if [[ -f $GTM_SERVICE_DIR/gre-keepalive-$tid.service ]]; then
        systemctl disable --now "gre-keepalive-$tid" || return 1
    fi
    systemctl disable --now "gre-tun-$tid" || return 1
    rm -f "$GTM_SERVICE_DIR/gre-tun-$tid.service" "$GTM_SERVICE_DIR/gre-keepalive-$tid.service" || return 1
    systemctl daemon-reload
}

gtm_owned_gre() {
    local tid=$1 line count=0
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line == ExecStart=* || $line == ExecStop=* || $line == ExecStopPost=* ]] || continue
        [[ $line =~ ^Exec(Start|Stop|StopPost)=-?/sbin/ip[[:space:]] ]] || return 1
        [[ $line != *';'* && $line != *'`'* && $line != *'$'* && $line != *'%'* ]] || return 1
        [[ $line == *"gre$tid "* || $line == *"gre-out-$tid "* || $line == *"gre$tid" || $line == *"gre-out-$tid" ]] || return 1
        ((count+=1))
    done < "$GTM_SERVICE_DIR/gre-tun-$tid.service"
    ((count>=5))
}
