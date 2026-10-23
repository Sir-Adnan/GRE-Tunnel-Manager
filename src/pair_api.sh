# Closed paired-create boundary. Every check, compare and mutation runs under
# the existing manager lock. Fingerprints never contain native config text.
gtm_pair_service() {
    [[ $1 =~ ^gre-tun-([1-9][0-9]{0,2})$ ]] && gtm_uint "${BASH_REMATCH[1]}" 1 250 && return 0
    [[ $1 =~ ^gtm-frp-(entrance|destination)-[a-zA-Z0-9_-]{1,32}$ ]]
}

# These paired presets never create keepalives or WSS gateways. Existing or
# subsequently introduced siblings must not be removed by legacy delete helpers.
gtm_pair_auxiliary_absent() {
    local id=$1 auxiliary='' config=''
    case $id in
        gre-tun-*) auxiliary="gre-keepalive-${id#gre-tun-}";;
        gtm-frp-entrance-*) auxiliary="gtm-gateway-${id#gtm-frp-entrance-}"; config="$GTM_CONFIG_DIR/$auxiliary.conf";;
        *) return 0;;
    esac
    [[ ! -e $GTM_SERVICE_DIR/$auxiliary.service && ! -L $GTM_SERVICE_DIR/$auxiliary.service ]] || return 1
    [[ -z $config || ( ! -e $config && ! -L $config ) ]]
}

gtm_pair_fingerprint() {
    local id=$1 file parts sum
    gtm_pair_service "$id" || return 1
    gtm_pair_auxiliary_absent "$id" || return 1
    file="$GTM_SERVICE_DIR/$id.service"
    [[ -f $file && ! -L $file ]] || return 1
    if [[ $id == gre-tun-* ]]; then
        gtm_owned_gre "${id#gre-tun-}" || return 1
        parts=$(sha256sum "$file") || return 1
    else
        [[ -f $GTM_CONFIG_DIR/$id.toml && ! -L $GTM_CONFIG_DIR/$id.toml ]] || return 1
        parts=$(sha256sum "$file" "$GTM_CONFIG_DIR/$id.toml") || return 1
    fi
    sum=$(printf '%s\n' "$parts" | sha256sum) || return 1
    printf '%s\n' "${sum%% *}"
}

gtm_pair_revision() {
    local id=$1
    gtm_pair_service "$id" || return 1
    gtm_pair_auxiliary_absent "$id" || return 1
    [[ ! -e $GTM_SERVICE_DIR/$id.service && ! -L $GTM_SERVICE_DIR/$id.service && ! -e $GTM_CONFIG_DIR/$id.toml && ! -L $GTM_CONFIG_DIR/$id.toml ]] || return 1
    gtm_load_records || return 1
    { printf '%s\n' "$id"; ((${#GTM_RECORDS[@]}==0)) || printf '%s\n' "${GTM_RECORDS[@]}"; } | sha256sum | cut -d' ' -f1
}

gtm_pair_gre_check() {
    local tid=$1 role=$2 remote=$3 bind=$4 mtu=$5 iface maximum=1472
    gtm_uint "$tid" 1 250 && [[ $role == kharej || $role == iran ]] && gtm_ip "$remote" && gtm_ip "$bind" || return 1
    if [[ $remote == *:* ]]; then maximum=1452; [[ $bind == *:* ]] || return 1
    else [[ $bind != *:* ]] || return 1; fi
    gtm_uint "$mtu" 1280 "$maximum" && gtm_local_address "$bind" && gtm_need ip && gtm_need systemctl && gtm_need sha256sum || return 1
    tid=$((10#$tid)); iface="gre$tid"; [[ $role != iran ]] || iface="gre-out-$tid"
    ! ip link show "$iface" >/dev/null 2>&1 || return 1
    # No default/policy-route changes. Refuse assigned internal address conflicts;
    # GRE still creates its normal connected routes, protected by a root lease.
    ! ip -o addr show | awk '{print $4}' | grep -Eq "^(10\.0\.$tid\.|fd00:$tid:)" || return 1
    gtm_pair_revision "gre-tun-$tid"
}

gtm_pair_frp_check() {
    local bin tmp id="gtm-frp-$P_ROLE-$P_NAME"
    gtm_frp_validate && gtm_need sha256sum || return 1
    if [[ $P_ROLE == entrance ]]; then
        gtm_local_address "$P_HOST" && gtm_port_available tcp "$P_HOST" "$P_CONTROL" && gtm_port_available "$P_PROTO" "$P_HOST" "$P_PUBLIC" || return 1
        [[ $P_TRANSPORT != quic ]] || gtm_port_available udp "$P_HOST" "$P_CONTROL" || return 1
        bin=$(command -v frps) || return 1
    else bin=$(command -v frpc) || return 1; fi
    tmp=$(mktemp "$GTM_RUN_DIR/pair-frp.XXXXXX") || return 1
    if ! { gtm_frp_render > "$tmp" && "$bin" verify -c "$tmp" >&2; }; then rm -f "$tmp"; return 1; fi
    rm -f "$tmp"
    gtm_pair_revision "$id"
}

gtm_pair_api() {
    # Exit 75 is reserved for refusal BEFORE any network mutation. Once create
    # begins, failures use normal failure codes and require receipt inspection.
    local operation=$1 revision='' actual id result=1
    shift
    gtm_prepare && gtm_lock || return 1
    case $operation in
        pair-check-gre|pair-apply-gre)
            if [[ $operation == pair-apply-gre ]]; then revision=${1:-}; shift; result=75; fi
            if (($#==5)); then
                actual=$(gtm_pair_gre_check "$@") || { gtm_unlock; [[ $operation != pair-apply-gre ]] || return 75; return 1; }
                if [[ $operation == pair-check-gre ]]; then printf '%s\n' "$actual"; result=0
                elif [[ $revision =~ ^[a-f0-9]{64}$ && $revision == "$actual" ]]; then
                    id="gre-tun-$((10#$1))"
                    gtm_link_create "$@" >&2 && gtm_pair_fingerprint "$id"; result=$?
                fi
            fi;;
        pair-check-frp|pair-apply-frp)
            if [[ $operation == pair-apply-frp ]]; then revision=${1:-}; shift; result=75; fi
            if (($#==0)) && gtm_pair_frp_parse; then
                actual=$(gtm_pair_frp_check) || { unset P_TOKEN; gtm_unlock; [[ $operation != pair-apply-frp ]] || return 75; return 1; }
                if [[ $operation == pair-check-frp ]]; then printf '%s\n' "$actual"; result=0
                elif [[ $revision =~ ^[a-f0-9]{64}$ && $revision == "$actual" ]]; then
                    id="gtm-frp-$P_ROLE-$P_NAME"
                    gtm_frp_create >&2 && gtm_pair_fingerprint "$id"; result=$?
                fi
                unset P_TOKEN
            fi;;
        pair-verify|pair-delete)
            if (($#==2)) && gtm_pair_service "$1" && [[ $2 =~ ^[a-f0-9]{64}$ ]]; then
                id=$1; actual=$(gtm_pair_fingerprint "$id") || { gtm_unlock; return 1; }
                if [[ $actual == "$2" ]]; then
                    if [[ $operation == pair-verify ]]; then result=0
                    elif [[ $id == gre-tun-* ]]; then
                        gtm_confirm() { return 0; }; gtm_link_delete "${id#gre-tun-}"; result=$?
                    else gtm_reverse_delete "$id"; result=$?; fi
                fi
            fi;;
    esac
    gtm_unlock
    return "$result"
}
