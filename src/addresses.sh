# Address tools. After an IP change, list where owned resources use an address
# and replace it; give additional addresses their own owned units. Only manager
# units, reverse configs and connection records are read or rewritten.
GTM_EXTRA_MAX=32
GTM_EXTRA_TABLE=25200

gtm_same_family() { [[ ( $1 == *:* && $2 == *:* ) || ( $1 != *:* && $2 != *:* ) ]]; }

# Sets G_REMOTE and G_BIND from an owned GRE unit's tunnel line.
gtm_gre_endpoints() {
    local tid=$1 line pattern='^ExecStart=/sbin/ip( -6)? tunnel add [^ ]+ mode (gre|ip6gre) remote ([^ ]+) local ([^ ]+)( |$)'
    G_REMOTE=''; G_BIND=''
    gtm_owned_gre "$tid" || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line =~ $pattern ]] || continue
        G_REMOTE=${BASH_REMATCH[3]}; G_BIND=${BASH_REMATCH[4]}
    done < "$GTM_SERVICE_DIR/gre-tun-$tid.service"
    gtm_ip "$G_REMOTE" && gtm_ip "$G_BIND"
}

# "local ADDRESS" or "remote ADDRESS" for each address line of an owned reverse
# config; loopback and wildcard binds are not addresses anyone changes.
gtm_reverse_uses() {
    local file=$1 line key value pattern='^(bindAddr|proxyBindAddr|serverAddr|bind_addr|remote_addr) = "([^"]+)"$'
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line =~ $pattern ]] || continue
        key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}
        if [[ $key == bind_addr || $key == remote_addr ]]; then
            if [[ $value =~ ^\[([0-9a-fA-F:]+)\]:[0-9]+$ || $value =~ ^([0-9.]+):[0-9]+$ ]]; then value=${BASH_REMATCH[1]}; else continue; fi
        fi
        gtm_ip "$value" && [[ $value != 127.0.0.1 && $value != ::1 ]] && ! gtm_wildcard "$value" || continue
        case $key in serverAddr|remote_addr) printf 'remote %s\n' "$value";; *) printf 'local %s\n' "$value";; esac
    done < "$file"
}

# One row per use: USE ADDRESS KIND ID PRESENT EDITABLE. USE is local (this
# server's address) or remote (another server's); PRESENT is 1/0 for local
# addresses still on the server and - for remote ones. Reverse WSS entrances
# also bind a gateway this tool does not rewrite (EDITABLE 0).
gtm_address_uses() {
    local unit tid file id line target present editable use address
    local -a targets=()
    local -A seen=()
    for unit in "$GTM_SERVICE_DIR"/gre-tun-*.service; do
        [[ -f $unit && ! -L $unit ]] || continue
        tid=${unit##*/gre-tun-}; tid=${tid%.service}
        gtm_uint "$tid" 1 250 && gtm_gre_endpoints "$tid" 2>/dev/null || continue
        present=0; gtm_local_address "$G_BIND" 2>/dev/null && present=1
        printf 'local\t%s\tgre\tgre-tun-%d\t%d\t1\n' "$G_BIND" "$((10#$tid))" "$present"
        printf 'remote\t%s\tgre\tgre-tun-%d\t-\t1\n' "$G_REMOTE" "$((10#$tid))"
    done
    gtm_load_records || return 1
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        if ! gtm_wildcard "$R_BIND"; then
            present=0; gtm_local_address "$R_BIND" 2>/dev/null && present=1
            printf 'local\t%s\tconnection\t%s\t%d\t1\n' "$R_BIND" "$R_ID" "$present"
        fi
        seen=(); IFS=, read -r -a targets <<< "$R_TARGETS"
        for target in "${targets[@]}"; do
            gtm_target "$target" && ((EP_HOST == 0)) || continue
            gtm_key_of "$EP_IP" && [[ ! ${seen[$GTM_KEY]+set} ]] || continue
            seen[$GTM_KEY]=1
            printf 'remote\t%s\tconnection\t%s\t-\t1\n' "$EP_IP" "$R_ID"
        done
    done
    for file in "$GTM_CONFIG_DIR"/gtm-frp-*.toml "$GTM_CONFIG_DIR"/gtm-rathole-*.toml; do
        [[ -f $file && ! -L $file ]] || continue
        id=${file##*/}; id=${id%.toml}
        gtm_metadata_id "$id" || continue
        editable=1; [[ ! -e $GTM_CONFIG_DIR/gtm-gateway-${id#gtm-frp-entrance-}.conf || $id != gtm-frp-entrance-* ]] || editable=0
        seen=()
        while read -r use address; do
            gtm_key_of "$address" && [[ ! ${seen[$use$GTM_KEY]+set} ]] || continue
            seen[$use$GTM_KEY]=1
            present=-
            if [[ $use == local ]]; then present=0; gtm_local_address "$address" 2>/dev/null && present=1; fi
            printf '%s\t%s\treverse\t%s\t%s\t%d\n' "$use" "$address" "$id" "$present" "$editable"
        done < <(gtm_reverse_uses "$file")
    done
}

# Rewrites one owned GRE unit's USE address from OLD to NEW and restarts it if
# it was running. A failed restart restores the previous unit.
gtm_gre_readdress() {
    local tid=$1 old=$2 new=$3 use=$4 unit original updated line pattern active=0 field
    unit="$GTM_SERVICE_DIR/gre-tun-$tid.service"
    gtm_gre_endpoints "$tid" || return 1
    field=$G_REMOTE; [[ $use == remote ]] || field=$G_BIND
    [[ $(gtm_ip_key "$field") == "$(gtm_ip_key "$old")" ]] || return 1
    pattern='^(ExecStart=/sbin/ip( -6)? tunnel add [^ ]+ mode (gre|ip6gre) )remote ([^ ]+) local ([^ ]+)( .*)?$'
    original=$(<"$unit") || return 1
    updated=''
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ $line =~ $pattern ]]; then
            if [[ $use == remote ]]; then line="${BASH_REMATCH[1]}remote $new local ${BASH_REMATCH[5]}${BASH_REMATCH[6]}"
            else line="${BASH_REMATCH[1]}remote ${BASH_REMATCH[4]} local $new${BASH_REMATCH[6]}"; fi
        fi
        updated+="$line"$'\n'
    done <<< "$original"
    systemctl is-active --quiet "gre-tun-$tid" && active=1
    printf '%s' "$updated" > "$unit.tmp" && chmod 644 "$unit.tmp" && mv "$unit.tmp" "$unit" || { rm -f "$unit.tmp"; return 1; }
    gtm_owned_gre "$tid" && systemctl daemon-reload && { ((active == 0)) || systemctl restart "gre-tun-$tid"; } && return 0
    printf '%s\n' "$original" > "$unit.tmp" && chmod 644 "$unit.tmp" && mv "$unit.tmp" "$unit"
    systemctl daemon-reload; ((active == 0)) || systemctl restart "gre-tun-$tid"
    return 1
}

# Rewrites one owned reverse config, checks it and restarts the instance. WSS
# entrances keep a gateway bound to the address and are refused.
gtm_reverse_readdress() {
    local id=$1 old=$2 new=$3 use=$4 file original updated line key value host bin active=0 changed=0
    local pattern='^(bindAddr|proxyBindAddr|serverAddr|bind_addr|remote_addr) = "([^"]+)"$'
    file="$GTM_CONFIG_DIR/$id.toml"
    gtm_metadata_id "$id" && [[ $id == gtm-frp-* || $id == gtm-rathole-* ]] && [[ -f $file && ! -L $file ]] || return 1
    [[ $id != gtm-frp-entrance-* || ! -e $GTM_CONFIG_DIR/gtm-gateway-${id#gtm-frp-entrance-}.conf ]] || { gtm_error "$id uses a WSS gateway; recreate it with the new address."; return 1; }
    original=$(<"$file") || return 1
    updated=''
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ $line =~ $pattern ]]; then
            key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}; host=$value
            if [[ $key == bind_addr || $key == remote_addr ]]; then
                if [[ $value =~ ^\[([0-9a-fA-F:]+)\]:[0-9]+$ || $value =~ ^([0-9.]+):[0-9]+$ ]]; then host=${BASH_REMATCH[1]}; else host=''; fi
            fi
            if [[ -n $host ]] && gtm_ip "$host" && [[ $(gtm_ip_key "$host") == "$(gtm_ip_key "$old")" ]]; then
                case $key in serverAddr|remote_addr) [[ $use == remote ]];; *) [[ $use == local ]];; esac && {
                    if [[ $value == "["* ]]; then value="[$new]${value#*]}"
                    elif [[ $value != "$host" ]]; then value="$new${value#"$host"}"
                    else value=$new; fi
                    line="$key = \"$value\""; changed=1
                }
            fi
        fi
        updated+="$line"$'\n'
    done <<< "$original"
    ((changed)) || return 1
    printf '%s' "$updated" > "$file.tmp" && chmod 600 "$file.tmp" || { rm -f "$file.tmp"; return 1; }
    if [[ $id == gtm-frp-* ]]; then
        if [[ $id == gtm-frp-entrance-* ]]; then bin=$(command -v frps); else bin=$(command -v frpc); fi
        [[ -n $bin ]] && "$bin" verify -c "$file.tmp" >/dev/null || { rm -f "$file.tmp"; gtm_error "$id: the new configuration did not verify."; return 1; }
    fi
    systemctl is-active --quiet "$id" && active=1
    mv "$file.tmp" "$file" || { rm -f "$file.tmp"; return 1; }
    if ((active == 0)); then return 0; fi
    if systemctl restart "$id"; then
        sleep 1
        systemctl is-active --quiet "$id" && return 0
    fi
    printf '%s\n' "$original" > "$file.tmp" && chmod 600 "$file.tmp" && mv "$file.tmp" "$file"
    systemctl restart "$id"
    return 1
}

# Replaces OLD with NEW for one USE in the listed owned items ("all" = every
# use of OLD). Records go through gtm_commit (restore point and rollback);
# units and reverse configs follow one by one and are restored if they fail.
# Prints "result ID done|failed". Caller holds the manager lock.
gtm_address_replace() {
    local old=$1 new=$2 use=$3 old_key new_key row r_use r_address r_kind r_id r_present r_editable item found line target rest index uses result=0 changed=0
    shift 3 || return 2
    gtm_ip "$old" && gtm_ip "$new" && [[ $use == local || $use == remote ]] && (($# >= 1 && $# <= 64)) || { gtm_error 'Enter the old address, the new address and local or remote.'; return 2; }
    ! gtm_wildcard "$old" && ! gtm_wildcard "$new" || { gtm_error 'Use specific addresses, not 0.0.0.0 or ::.'; return 2; }
    gtm_same_family "$old" "$new" || { gtm_error 'Both addresses must be IPv4, or both IPv6.'; return 2; }
    old_key=$(gtm_ip_key "$old") && new_key=$(gtm_ip_key "$new") || return 2
    [[ $old_key != "$new_key" ]] || { gtm_error 'The new address is the same as the old one.'; return 2; }
    if [[ $use == local ]]; then gtm_local_address "$new" || { gtm_error "The new address is not on this server: $new"; return 1; }; fi
    local -a matches=() chosen=() records=() targets=()
    local -A wanted=()
    uses=$(gtm_address_uses) && gtm_load_records || return 1
    while IFS= read -r row; do
        [[ -n $row ]] || continue
        IFS=$'\t' read -r r_use r_address r_kind r_id r_present r_editable <<< "$row"
        [[ $r_use == "$use" && $(gtm_ip_key "$r_address") == "$old_key" ]] && matches+=("$r_kind $r_id $r_editable")
    done <<< "$uses"
    for item in "$@"; do
        [[ $item == all || $item =~ ^(gre-tun-[0-9]{1,3}|F[0-9]{6}|gtm-(frp|rathole)-(entrance|destination)-[a-zA-Z0-9_-]{1,32})$ ]] || { gtm_error "Unknown item: $item"; return 2; }
        found=0
        for row in "${matches[@]}"; do
            read -r r_kind r_id r_editable <<< "$row"
            [[ $item == all || $item == "$r_id" ]] || continue
            found=1
            [[ ${wanted[$r_id]+set} ]] || chosen+=("$row")
            wanted[$r_id]=$r_kind
        done
        ((found)) || { gtm_error "$item does not use $old."; return 1; }
    done
    # Connections first, in one commit: a failure here changes nothing else.
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        if [[ ${wanted[$R_ID]-} == connection ]]; then
            if [[ $use == local ]]; then
                R_BIND=$new
            else
                IFS=, read -r -a targets <<< "$R_TARGETS"
                for index in "${!targets[@]}"; do
                    target=${targets[$index]}
                    gtm_target "$target" && ((EP_HOST == 0)) && [[ $(gtm_ip_key "$EP_IP") == "$old_key" ]] || continue
                    if [[ $target == "["* ]]; then rest=${target#*]}; targets[$index]="[$new]$rest"
                    else rest=${target#"$EP_IP"}; targets[$index]="$new$rest"; fi
                done
                R_TARGETS=$(IFS=,; printf '%s' "${targets[*]}")
            fi
            line=$(gtm_record_emit)
            gtm_record_validate "$line" || { gtm_error "$R_ID: the changed connection is not valid."; return 1; }
            if [[ $use == local && $R_ENABLED == 1 ]]; then
                gtm_listener_check "$R_PROTO" "$R_BIND" "$R_PORT" && gtm_legacy_listener_check "$R_PROTO" "$R_BIND" "$R_PORT" || return 1
            fi
            changed=1
        fi
        records+=("$line")
    done
    if ((changed)); then
        GTM_RECORDS=("${records[@]}")
        gtm_commit >&2 || return 1
        for row in "${chosen[@]}"; do read -r r_kind r_id _ <<< "$row"; [[ $r_kind != connection ]] || printf 'result\t%s\tdone\n' "$r_id"; done
    fi
    for row in "${chosen[@]}"; do
        read -r r_kind r_id r_editable <<< "$row"
        case $r_kind in
            gre) if gtm_gre_readdress "${r_id#gre-tun-}" "$old" "$new" "$use"; then printf 'result\t%s\tdone\n' "$r_id"; else printf 'result\t%s\tfailed\n' "$r_id"; result=1; fi;;
            reverse) if gtm_reverse_readdress "$r_id" "$old" "$new" "$use"; then printf 'result\t%s\tdone\n' "$r_id"; else printf 'result\t%s\tfailed\n' "$r_id"; result=1; fi;;
        esac
    done
    ((result == 0)) || gtm_error 'Some items were not changed; they keep the old address.'
    return "$result"
}

# Paired readdress (Nodes): a digest of the owned GRE units whose USE address
# is ADDRESS. Check and apply compare it, like paired create revisions.
gtm_readdress_digest() {
    local address=$1 use=$2 key unit tid field parts=''
    key=$(gtm_ip_key "$address") || return 1
    for unit in "$GTM_SERVICE_DIR"/gre-tun-*.service; do
        [[ -f $unit && ! -L $unit ]] || continue
        tid=${unit##*/gre-tun-}; tid=${tid%.service}
        gtm_uint "$tid" 1 250 && gtm_gre_endpoints "$tid" 2>/dev/null || continue
        field=$G_REMOTE; [[ $use == remote ]] || field=$G_BIND
        [[ $(gtm_ip_key "$field") == "$key" ]] || continue
        parts+=$(sha256sum "$unit")$'\n' || return 1
    done
    [[ -n $parts ]] || { gtm_error "No managed GRE tunnel uses $address."; return 1; }
    printf '%s' "$parts" | sha256sum | cut -d' ' -f1
}

gtm_readdress_args() {
    gtm_ip "$1" && gtm_ip "$2" && gtm_same_family "$1" "$2" && [[ $3 == local || $3 == remote ]] || return 1
    ! gtm_wildcard "$1" && ! gtm_wildcard "$2" && [[ $(gtm_ip_key "$1") != "$(gtm_ip_key "$2")" ]]
}

# readdress-apply REVISION OLD NEW USE: exit 75 when the units changed since
# the check; prints the digest of the rewritten units as the fingerprint.
gtm_readdress_apply() {
    local revision=$1 old=$2 new=$3 use=$4 actual unit tid field result=0 key
    [[ $revision =~ ^[a-f0-9]{64}$ ]] && gtm_readdress_args "$old" "$new" "$use" || return 2
    actual=$(gtm_readdress_digest "$old" "$use") && [[ $actual == "$revision" ]] || return 75
    key=$(gtm_ip_key "$old")
    for unit in "$GTM_SERVICE_DIR"/gre-tun-*.service; do
        [[ -f $unit && ! -L $unit ]] || continue
        tid=${unit##*/gre-tun-}; tid=${tid%.service}
        gtm_uint "$tid" 1 250 && gtm_gre_endpoints "$tid" 2>/dev/null || continue
        field=$G_REMOTE; [[ $use == remote ]] || field=$G_BIND
        [[ $(gtm_ip_key "$field") == "$key" ]] || continue
        gtm_gre_readdress "$tid" "$old" "$new" "$use" || result=1
    done
    ((result == 0)) || return 1
    gtm_readdress_digest "$new" "$use"
}

# Additional addresses: gtm-addr-N.service adds ADDRESS/PREFIX to IFACE and,
# with a gateway, a policy route so replies from it leave through that gateway.
gtm_owned_addr() {
    local n=$1 file line count=0
    file="$GTM_SERVICE_DIR/gtm-addr-$n.service"
    [[ -f $file && ! -L $file ]] && IFS= read -r line < "$file" && [[ $line == '# GTM managed address v1' ]] || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line == Exec* ]] || continue
        [[ $line =~ ^Exec(Start|StartPre|Stop)=-?/sbin/ip[[:space:]] && $line != *';'* && $line != *'`'* && $line != *'$'* && $line != *'%'* ]] || return 1
        ((count+=1))
    done < "$file"
    ((count >= 2))
}

gtm_extra_render() {
    local n=$1 address=$2 prefix=$3 iface=$4 gateway=$5 family='' table=$((GTM_EXTRA_TABLE + 10#$1))
    [[ $address != *:* ]] || family=' -6'
    printf '# GTM managed address v1\n[Unit]\nDescription=Additional address %s/%s on %s\nWants=network-online.target\nAfter=network-online.target\nBefore=gre-manager-forwarding.service\n' "$address" "$prefix" "$iface"
    printf '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/sbin/ip address replace %s/%s dev %s\n' "$address" "$prefix" "$iface"
    if [[ $gateway != - ]]; then
        printf 'ExecStartPre=-/sbin/ip%s rule del from %s table %d priority %d\n' "$family" "$address" "$table" "$table"
        printf 'ExecStart=/sbin/ip%s route replace default via %s dev %s table %d\n' "$family" "$gateway" "$iface" "$table"
        printf 'ExecStart=/sbin/ip%s rule add from %s table %d priority %d\n' "$family" "$address" "$table" "$table"
        printf 'ExecStop=-/sbin/ip%s rule del from %s table %d priority %d\n' "$family" "$address" "$table" "$table"
        printf 'ExecStop=-/sbin/ip%s route flush table %d\n' "$family" "$table"
    fi
    printf 'ExecStop=-/sbin/ip address del %s/%s dev %s\n[Install]\nWantedBy=multi-user.target\n' "$address" "$prefix" "$iface"
}

# Rows: N ADDRESS/PREFIX IFACE GATEWAY ACTIVE(1/0) PRESENT(1/0).
gtm_extra_list() {
    local unit n line address='' iface='' gateway active present pattern='^ExecStart=/sbin/ip address replace ([^ /]+)/([0-9]+) dev ([^ ]+)$' route='^ExecStart=/sbin/ip( -6)? route replace default via ([^ ]+) dev '
    for unit in "$GTM_SERVICE_DIR"/gtm-addr-*.service; do
        n=${unit##*/gtm-addr-}; n=${n%.service}
        gtm_uint "$n" 1 "$GTM_EXTRA_MAX" && gtm_owned_addr "$n" || continue
        address=''; gateway=-
        while IFS= read -r line || [[ -n $line ]]; do
            if [[ $line =~ $pattern ]]; then address="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"; iface=${BASH_REMATCH[3]}
            elif [[ $line =~ $route ]]; then gateway=${BASH_REMATCH[2]}; fi
        done < "$unit"
        [[ -n $address ]] || continue
        active=0; systemctl is-active --quiet "gtm-addr-$n" && active=1
        present=0; gtm_local_address "${address%/*}" 2>/dev/null && present=1
        printf '%d\t%s\t%s\t%s\t%d\t%d\n' "$((10#$n))" "$address" "$iface" "$gateway" "$active" "$present"
    done
}

# extra-add ADDRESS/PREFIX IFACE GATEWAY|-: creates and starts the next unit,
# then reports whether the address is on the server and routes from it.
gtm_extra_add() {
    local cidr=$1 iface=$2 gateway=$3 address prefix n unit maximum=32 route probe
    address=${cidr%/*}; prefix=${cidr##*/}
    [[ $cidr == */* ]] && gtm_ip "$address" && ! gtm_wildcard "$address" || { gtm_error 'Enter the address with its prefix, like 203.0.113.40/32.'; return 2; }
    [[ $address != *:* ]] || maximum=128
    gtm_uint "$prefix" 8 "$maximum" && gtm_iface "$iface" && [[ $iface != any ]] || { gtm_error 'Choose a network interface and a valid prefix.'; return 2; }
    [[ $gateway == - ]] || { gtm_ip "$gateway" && gtm_same_family "$address" "$gateway" && ! gtm_wildcard "$gateway"; } || { gtm_error 'The gateway must be an address of the same family.'; return 2; }
    gtm_need ip && gtm_need systemctl || return 1
    ip link show dev "$iface" >/dev/null 2>&1 || { gtm_error "Network interface not found: $iface"; return 1; }
    ! gtm_local_address "$address" 2>/dev/null || { gtm_error "The address is already on this server: $address"; return 1; }
    for ((n=1; n<=GTM_EXTRA_MAX; n++)); do
        unit="$GTM_SERVICE_DIR/gtm-addr-$n.service"
        [[ -e $unit || -L $unit ]] || break
    done
    ((n <= GTM_EXTRA_MAX)) || { gtm_error "At most $GTM_EXTRA_MAX additional addresses are managed."; return 1; }
    gtm_extra_render "$n" "$address" "$((10#$prefix))" "$iface" "$gateway" > "$unit.tmp" && chmod 644 "$unit.tmp" && mv "$unit.tmp" "$unit" || { rm -f "$unit.tmp"; return 1; }
    if ! { systemctl daemon-reload && systemctl enable --now "gtm-addr-$n"; }; then
        systemctl disable --now "gtm-addr-$n"; rm -f "$unit"; systemctl daemon-reload
        gtm_error 'The address could not be added; nothing was kept.'; return 1
    fi
    printf 'extra\t%d\n' "$n"
    if gtm_local_address "$address" 2>/dev/null; then printf 'check\tpresent\t1\n'; else printf 'check\tpresent\t0\n'; fi
    # A route from the address to its gateway (or the internet) means replies can leave.
    probe=$gateway
    if [[ $probe == - ]]; then probe=1.1.1.1; [[ $address != *:* ]] || probe=2606:4700:4700::1111; fi
    route=$(ip route get "$probe" from "$address" 2>/dev/null) || route=''
    if [[ -n $route ]]; then printf 'check\troute\t1\n'; else printf 'check\troute\t0\n'; fi
    gtm_kernel_apply >/dev/null 2>&1 || printf 'Warning: owned kernel rules could not be reapplied.\n' >&2
}

# extra-delete N: refused while a connection, tunnel or reverse instance still
# uses the address.
gtm_extra_delete() {
    local n=$1 row address use r_address kind id uses
    gtm_uint "$n" 1 "$GTM_EXTRA_MAX" || return 2
    n=$((10#$n))
    gtm_owned_addr "$n" || { gtm_error 'Unrecognized address unit; inspect it manually.'; return 1; }
    row=$(gtm_extra_list | awk -F'\t' -v n="$n" '$1 == n {print $2}')
    address=${row%/*}
    if [[ -n $address ]]; then
        uses=$(gtm_address_uses) || return 1
        while IFS=$'\t' read -r use r_address kind id _; do
            [[ $use == local && -n $r_address && $(gtm_ip_key "$r_address") == "$(gtm_ip_key "$address")" ]] || continue
            gtm_error "$id still uses $address; change it first."; return 1
        done <<< "$uses"
    fi
    systemctl disable --now "gtm-addr-$n" || return 1
    rm -f "$GTM_SERVICE_DIR/gtm-addr-$n.service" && systemctl daemon-reload || return 1
    gtm_kernel_apply >/dev/null 2>&1 || printf 'Warning: owned kernel rules could not be reapplied.\n' >&2
    printf 'Additional address removed.\n'
}

# Locked API wrappers.
gtm_address_api() {
    local operation=$1 result
    shift
    case $operation in
        address-uses) (($#==0)) || return 2; gtm_address_uses; return $?;;
        extra-list) (($#==0)) || return 2; gtm_extra_list; return $?;;
    esac
    gtm_prepare && gtm_lock || return 2
    case $operation in
        address-replace) gtm_address_replace "$@";;
        readdress-check) (($#==3)) && gtm_readdress_args "$@" && gtm_readdress_digest "$1" "$3";;
        readdress-apply) (($#==4)) && gtm_readdress_apply "$@";;
        extra-add) (($#==3)) && gtm_extra_add "$@";;
        extra-delete) (($#==1)) && gtm_extra_delete "$1";;
        *) false;;
    esac
    result=$?; gtm_unlock; return "$result"
}
