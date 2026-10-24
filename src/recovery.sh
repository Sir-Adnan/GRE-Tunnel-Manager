# Portable recovery accepts typed records only. No imported commands or units.
gtm_recovery_revision() (
    local file
    set -o pipefail
    {
        for file in "$GTM_STATE" "$GTM_CONFIG_DIR/id-counter" "$GTM_CONFIG_DIR/resource-names.tsv" "$GTM_SERVICE_DIR"/gre-tun-*.service "$GTM_SERVICE_DIR"/gtm-frp-*.service "$GTM_SERVICE_DIR"/gtm-rathole-*.service "$GTM_SERVICE_DIR"/gtm-gateway-*.service "$GTM_CONFIG_DIR"/gtm-frp-*.toml "$GTM_CONFIG_DIR"/gtm-rathole-*.toml "$GTM_CONFIG_DIR"/gtm-gateway-*.conf; do
            [[ -e $file || -L $file ]] || continue
            [[ -f $file && ! -L $file ]] || exit 1
            sha256sum "$file" || exit 1
        done
    } | sha256sum | cut -d ' ' -f 1
)

gtm_recovery_reverse_parse() {
    local line=$1 fields engine key cert internal
    fields=${line//[^$'\t']/}; ((${#fields}==15)) && [[ $line != *$'\r'* ]] || return 1
    IFS=$'\t' read -r engine P_NAME P_ROLE P_HOST P_CONTROL P_PUBLIC P_LOCAL_IP P_LOCAL_PORT P_PROTO P_TRANSPORT P_MUX P_TOKEN P_GROUP key cert internal <<< "$line"
    [[ $P_NAME =~ ^[a-zA-Z0-9_-]{1,32}$ ]] || return 1
    case $engine in
        frp) P_TLS_CA=$cert; P_GATEWAY_CERT=$cert; P_INTERNAL=$internal; gtm_frp_validate;;
        rathole)
            RATH_NAME=$P_NAME; RATH_ROLE=$P_ROLE; RATH_HOST=$P_HOST; RATH_CONTROL=$P_CONTROL; RATH_PUBLIC=$P_PUBLIC
            RATH_LOCAL_IP=$P_LOCAL_IP; RATH_LOCAL_PORT=$P_LOCAL_PORT; RATH_PROTO=$P_PROTO; RATH_TOKEN=$P_TOKEN; RATH_KEY=$key
            gtm_rathole_validate;;
        *) return 1;;
    esac
}

gtm_recovery_render() {
    local kind=$1 line
    IFS= read -r line || return 1
    ((${#line}<=4096)) || return 1
    case $kind in
        frp|rathole|gateway)
            if [[ $kind == gateway ]]; then [[ ${line%%$'\t'*} == frp ]] || return 1
            else [[ ${line%%$'\t'*} == "$kind" ]] || return 1; fi
            gtm_recovery_reverse_parse "$line" || return 1
            case $kind in frp) gtm_frp_render;; rathole) gtm_rathole_render;; gateway) [[ $P_TRANSPORT == wss && $P_ROLE == entrance ]] && gtm_wss_haproxy_render;; esac;;
        *) return 1;;
    esac
}

gtm_recovery_publish() {
    local source=$1 target=$2 mode=$3 candidate
    candidate=$(mktemp "${target%/*}/.recovery.XXXXXX") || return 1
    install -m "$mode" "$source" "$candidate" && mv -f "$candidate" "$target" || { rm -f "$candidate"; return 1; }
}

# Restore onto an empty managed installation. All imported resources stay paused.
# Complete validation/staging precedes the first persistent configuration write.
gtm_recovery_import() (
    local expected actual line kind data id tmp file result=0 maximum=0 value name hash count=0 counter_seen=0 resources=0
    local -a rows=() staged=() names=()
    IFS= read -r expected && [[ $expected =~ ^[a-f0-9]{64}$ ]] && gtm_prepare && gtm_lock || return 1
    actual=$(gtm_recovery_revision) && [[ $actual == "$expected" ]] || { gtm_error 'Server configuration changed; review the backup again.'; return 1; }
    gtm_load_records && ((${#GTM_RECORDS[@]}==0)) || { gtm_error 'Restore requires an empty managed installation.'; return 1; }
    for file in "$GTM_SERVICE_DIR"/gre-tun-*.service "$GTM_SERVICE_DIR"/gtm-frp-*.service "$GTM_SERVICE_DIR"/gtm-rathole-*.service "$GTM_CONFIG_DIR"/gtm-frp-*.toml "$GTM_CONFIG_DIR"/gtm-rathole-*.toml; do
        [[ ! -e $file && ! -L $file ]] || { gtm_error 'Existing tunnel files must be resolved before recovery.'; return 1; }
    done
    tmp=$(mktemp -d "$GTM_RUN_DIR/recovery.XXXXXX") || return 1
    trap 'rm -f "$tmp"/*; rmdir "$tmp"; gtm_unlock' EXIT
    local -A seen=() named=()
    while IFS= read -r line || [[ -n $line ]]; do
        ((count+=1)); ((${#line}<=16384 && count<=4096)) || return 1
        [[ $line == *$'\t'* ]] || return 1
        kind=${line%%$'\t'*}; data=${line#*$'\t'}
        case $kind in
            I) ((counter_seen==0 && count==1)) && gtm_uint "$data" 0 999999 || return 1; counter_seen=1; maximum=$((10#$data));;
            C)
                gtm_record_validate "$data" && [[ $R_ENABLED == 0 && $R_ID != F000000 && ! ${seen[$R_ID]+set} ]] || return 1
                seen[$R_ID]=1; value=$((10#${R_ID#F})); ((value<=maximum)) || maximum=$value
                rows+=("$data"); ((${#rows[@]}<=128)) || return 1;;
            G)
                ((resources+=1)); ((resources<=512)) || return 1
                local tid role remote bind mtu extra
                IFS=$'\t' read -r tid role remote bind mtu extra <<< "$data"
                [[ -z $extra ]] && gtm_uint "$tid" 1 250 && [[ $role == kharej || $role == iran ]] && gtm_ip "$remote" && gtm_ip "$bind" || return 1
                if [[ $remote == *:* ]]; then [[ $bind == *:* ]] && gtm_uint "$mtu" 1280 1452 || return 1
                else [[ $bind != *:* ]] && gtm_uint "$mtu" 1280 1472 || return 1; fi
                id="gre-tun-$((10#$tid))"; [[ ! ${seen[$id]+set} ]] || return 1; seen[$id]=1
                gtm_link_render "$tid" "$role" "$remote" "$bind" "$mtu" > "$tmp/$id.service" || return 1
                staged+=("$id.service");;
            R)
                ((resources+=1)); ((resources<=512)) || return 1
                gtm_recovery_reverse_parse "$data" || return 1
                id="gtm-${data%%$'\t'*}-$P_ROLE-$P_NAME"; [[ ! ${seen[$id]+set} ]] || return 1; seen[$id]=1
                if [[ $id == gtm-frp-* ]]; then
                    gtm_frp_render > "$tmp/$id.toml" || return 1
                    local bin=/usr/local/bin/frpc; [[ $P_ROLE != entrance ]] || bin=/usr/local/bin/frps
                    gtm_relay_unit "$bin" "$GTM_CONFIG_DIR/$id.toml" "$P_NAME" > "$tmp/$id.service" || return 1
                    if [[ $P_TRANSPORT == wss && $P_ROLE == entrance ]]; then
                        local gateway="gtm-gateway-$P_NAME"
                        gtm_wss_haproxy_render > "$tmp/$gateway.conf" || return 1
                        gtm_relay_unit /usr/sbin/haproxy "$GTM_CONFIG_DIR/$gateway.conf" "$P_NAME" | sed "s|^ExecStart=.*|ExecStart=/usr/sbin/haproxy -Ws -f $GTM_CONFIG_DIR/$gateway.conf|; /After=network-online.target/a PartOf=$id.service\nAfter=$id.service" > "$tmp/$gateway.service" || return 1
                        sed -i "/After=network-online.target/a Wants=$gateway.service" "$tmp/$id.service" || return 1
                        staged+=("$gateway.conf" "$gateway.service")
                    fi
                else
                    gtm_rathole_render > "$tmp/$id.toml" && gtm_rathole_unit /usr/local/bin/rathole "$GTM_CONFIG_DIR/$id.toml" > "$tmp/$id.service" || return 1
                fi
                staged+=("$id.toml" "$id.service");;
            N)
                IFS=$'\t' read -r id name extra <<< "$data"
                gtm_metadata_id "$id" && [[ -z $extra && ${seen[$id]+set} && ! ${named[$id]+set} && -f $tmp/$id.service ]] && gtm_name "$name" || return 1
                named[$id]=1
                hash=$(sha256sum "$tmp/$id.service") || return 1; names+=("$id"$'\t'"${hash%% *}"$'\t'"$name");;
            *) return 1;;
        esac
    done
    GTM_RECORDS=("${rows[@]}")
    gtm_write_records "$tmp/connections.tsv" && gtm_load_records "$tmp/connections.tsv" || return 1
    # Never clobber orphaned files, gateway configs or symbolic links.
    for file in "${staged[@]}"; do
        local root=$GTM_CONFIG_DIR; [[ $file != *.service ]] || root=$GTM_SERVICE_DIR
        [[ ! -e $root/$file && ! -L $root/$file ]] || { gtm_error 'Recovery file conflicts with an existing resource.'; return 1; }
        [[ $file != *.service || ( ! -e $GTM_SERVICE_DIR/multi-user.target.wants/$file && ! -L $GTM_SERVICE_DIR/multi-user.target.wants/$file ) ]] || { gtm_error 'A boot link already exists for this service; inspect it before recovery.'; return 1; }
        if [[ $file == *.service ]] && systemctl is-active --quiet "${file%.service}"; then gtm_error 'An imported service is already running; inspect the local installation.'; return 1; fi
    done
    [[ ! -L $GTM_CONFIG_DIR/id-counter && ! -L $GTM_CONFIG_DIR/resource-names.tsv ]] || return 1
    # Recovery saves desired data only: it starts no services or firewall rules.
    # Keep previous state/counter/metadata for a checked rollback on write failure.
    for file in connections.tsv id-counter resource-names.tsv; do
        [[ ! -e $GTM_CONFIG_DIR/$file ]] || cp -p "$GTM_CONFIG_DIR/$file" "$tmp/old-$file" || return 1
    done
    local -a written=()
    for file in "${staged[@]}"; do
        local root=$GTM_CONFIG_DIR mode=600; [[ $file != *.service ]] || { root=$GTM_SERVICE_DIR; mode=644; }
        if gtm_recovery_publish "$tmp/$file" "$root/$file" "$mode"; then written+=("$root/$file"); else result=1; break; fi
    done
    if ((result==0)); then
        if [[ -f $tmp/old-id-counter ]]; then
            IFS= read -r value < "$tmp/old-id-counter"
            gtm_uint "$value" 0 999999 || result=1
            [[ $result != 0 ]] || { ((10#$value<=maximum)) || maximum=$((10#$value)); }
        fi
        printf '%s\n' "$maximum" > "$tmp/id-counter"
        : > "$tmp/resource-names.tsv"
        ((${#names[@]}==0)) || printf '%s\n' "${names[@]}" > "$tmp/resource-names.tsv"
        for file in connections.tsv id-counter resource-names.tsv; do
            ((result==0)) && gtm_recovery_publish "$tmp/$file" "$GTM_CONFIG_DIR/$file" 600 || { result=1; break; }
        done
        ((result!=0)) || systemctl daemon-reload || result=1
    fi
    if ((result)); then
        for file in "${written[@]}"; do rm -f "$file" || gtm_error 'Recovery cleanup needs attention.'; done
        for file in connections.tsv id-counter resource-names.tsv; do
            if [[ -f $tmp/old-$file ]]; then gtm_recovery_publish "$tmp/old-$file" "$GTM_CONFIG_DIR/$file" 600 || gtm_error 'Recovery rollback needs attention.'
            else rm -f "$GTM_CONFIG_DIR/$file" || gtm_error 'Recovery rollback needs attention.'; fi
        done
        systemctl daemon-reload || gtm_error 'Reload needs attention.'
        return 1
    fi
    printf 'Recovery saved. All restored resources are paused. Install missing engines, review addresses and start resources explicitly.\n'
)
