# Domain destinations. Records keep the DNS name; rules and relay configs use the
# last addresses that resolved, so the packet path never waits for DNS and a
# failed lookup keeps the previous addresses. A minute timer refreshes due names.
GTM_DNS_MAX=16
GTM_DNS_UNIT=gre-manager-dns

gtm_dns_paths() {
    GTM_DNS_CACHE="$GTM_CONFIG_DIR/dns-cache.tsv"
    GTM_DNS_POLICY="$GTM_CONFIG_DIR/dns-policy.tsv"
    GTM_DNS_PENDING="$GTM_CONFIG_DIR/dns-pending"
}

# Prints the usable addresses of NAME in FAMILY (4 or 6), sorted and unique.
# GTM_DNS_LOOKUP overrides the resolver in tests.
gtm_dns_lookup() {
    local name=$1 family=$2 address output database=ahostsv4 count=0
    local -A seen=()
    gtm_hostname "$name" && [[ $family == 4 || $family == 6 ]] || return 1
    [[ $family == 4 ]] || database=ahostsv6
    if [[ -n ${GTM_DNS_LOOKUP:-} ]]; then output=$("$GTM_DNS_LOOKUP" "$name" "$family") || return 1
    else output=$(timeout 5 getent "$database" "$name") || return 1; fi
    while read -r address _; do
        [[ -n $address && ! ${seen[$address]+set} ]] || continue
        if [[ $family == 4 ]]; then
            gtm_ipv4 "$address" && [[ $address != 0.* && $address != 127.* ]] || continue
            (( ${address%%.*} < 224 )) || continue
        else
            gtm_ipv6 "$address" && gtm_key_of "$address" || continue
            [[ $GTM_KEY != 0000000000000000000000000000000[01] && $GTM_KEY != ff* && $GTM_KEY != 00000000000000000000ffff* ]] || continue
        fi
        seen[$address]=1
        printf '%s\n' "$address"
        ((++count < GTM_DNS_MAX)) || break
    done <<< "$output" | sort -V
}

# Loads the cache once per process into GTM_DNS_ADDR[name/family] and
# GTM_DNS_CHECKED[name/family]; policies into GTM_DNS_EVERY and GTM_DNS_MODE.
gtm_dns_load() {
    local name family checked list every mode
    [[ ${GTM_DNS_LOADED:-} == "$GTM_CONFIG_DIR" ]] && return 0
    gtm_dns_paths
    declare -gA GTM_DNS_ADDR=() GTM_DNS_CHECKED=() GTM_DNS_EVERY=() GTM_DNS_MODE=()
    if [[ -f $GTM_DNS_CACHE && ! -L $GTM_DNS_CACHE ]]; then
        while IFS=$'\t' read -r name family checked list; do
            gtm_hostname "$name" && [[ $family =~ ^[46]$ && $checked =~ ^[0-9]{1,12}$ && $list =~ ^[0-9a-fA-F.:,]{1,1200}$ ]] || continue
            GTM_DNS_ADDR[$name/$family]=$list; GTM_DNS_CHECKED[$name/$family]=$checked
        done < "$GTM_DNS_CACHE"
    fi
    if [[ -f $GTM_DNS_POLICY && ! -L $GTM_DNS_POLICY ]]; then
        while IFS=$'\t' read -r name every mode; do
            gtm_hostname "$name" && gtm_uint "$every" 1 60 && [[ $mode == all || $mode == first ]] || continue
            GTM_DNS_EVERY[$name]=$((10#$every)); GTM_DNS_MODE[$name]=$mode
        done < "$GTM_DNS_POLICY"
    fi
    GTM_DNS_LOADED=$GTM_CONFIG_DIR
}

gtm_dns_save() {
    local key tmp
    gtm_dns_paths
    tmp=$(mktemp "$GTM_DNS_CACHE.XXXXXX") || return 1
    for key in "${!GTM_DNS_ADDR[@]}"; do
        printf '%s\t%s\t%s\t%s\n' "${key%/*}" "${key##*/}" "${GTM_DNS_CHECKED[$key]:-0}" "${GTM_DNS_ADDR[$key]}"
    done | sort > "$tmp" && chmod 600 "$tmp" && mv "$tmp" "$GTM_DNS_CACHE" || { rm -f "$tmp"; return 1; }
}

# Sets the refresh interval (minutes) and multi-address mode of NAME.
gtm_dns_policy_set() {
    local name=$1 every=$2 mode=$3 key tmp
    gtm_hostname "$name" && gtm_uint "$every" 1 60 && [[ $mode == all || $mode == first ]] || { gtm_error 'Invalid DNS policy.'; return 1; }
    gtm_dns_load || return 1
    GTM_DNS_EVERY[$name]=$((10#$every)); GTM_DNS_MODE[$name]=$mode
    tmp=$(mktemp "$GTM_DNS_POLICY.XXXXXX") || return 1
    for key in "${!GTM_DNS_EVERY[@]}"; do
        printf '%s\t%s\t%s\n' "$key" "${GTM_DNS_EVERY[$key]}" "${GTM_DNS_MODE[$key]:-all}"
    done | sort > "$tmp" && chmod 600 "$tmp" && mv "$tmp" "$GTM_DNS_POLICY" || { rm -f "$tmp"; return 1; }
    # Desired policy must be reconciled even when the address list is unchanged.
    [[ ! -L $GTM_DNS_PENDING && ( ! -e $GTM_DNS_PENDING || -f $GTM_DNS_PENDING ) ]] && : > "$GTM_DNS_PENDING"
}

# The address family a record's names resolve in: kernel rules follow the bind;
# relays use IPv4 unless they listen on IPv6 only.
gtm_dns_family() { if [[ $R_BIND == *:* ]]; then printf 6; else printf 4; fi; }

# Prints "name<TAB>family" for every enabled record with a DNS destination.
gtm_dns_needed() {
    local line target family
    local -a targets=()
    local -A seen=()
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        [[ $R_ENABLED == 1 ]] || continue
        family=$(gtm_dns_family)
        IFS=, read -r -a targets <<< "$R_TARGETS"
        for target in "${targets[@]}"; do
            gtm_target "$target" && ((EP_HOST)) || continue
            [[ ${seen[$EP_IP/$family]+set} ]] && continue
            seen[$EP_IP/$family]=1
            printf '%s\t%s\n' "$EP_IP" "$family"
        done
    done
}

# Replaces R_TARGETS with literal destinations. A DNS name becomes its cached
# addresses (all, or the first with mode "first") with the name's port and weight.
# Returns 1 when no destination has an address yet; callers skip the record.
gtm_resolve_targets() {
    local target family list address port count=0 kept=0 skipped=''
    local -a targets=() out=() addresses=()
    local -A seen=()
    [[ $R_TARGETS =~ (^|,)[a-z0-9.-]*[a-z][a-z0-9.-]*: ]] || return 0
    gtm_dns_load || return 1
    family=$(gtm_dns_family)
    IFS=, read -r -a targets <<< "$R_TARGETS"
    for target in "${targets[@]}"; do
        gtm_target "$target" || return 1
        port=$(gtm_span_text "$EP_PORT" "$EP_LAST")
        if ((EP_HOST)); then
            list=${GTM_DNS_ADDR[$EP_IP/$family]-}
            [[ -n $list ]] || { skipped+=" $EP_IP"; continue; }
            IFS=, read -r -a addresses <<< "$list"
            [[ ${GTM_DNS_MODE[$EP_IP]:-all} == all ]] || addresses=("${addresses[0]}")
        else addresses=("$EP_IP"); fi
        for address in "${addresses[@]}"; do
            [[ ! ${seen[$address/$port]+set} ]] && ((count < 32)) || continue
            seen[$address/$port]=1; ((count+=1))
            out+=("$(gtm_address "$address" "$port")@$EP_WEIGHT")
        done
        ((kept+=1))
    done
    [[ -z $skipped ]] || printf 'Warning: %s has no resolved address yet for%s.\n' "$R_ID" "$skipped" >&2
    ((count)) || return 1
    R_TARGETS=$(IFS=,; printf '%s' "${out[*]}")
    # A name may resolve to fewer addresses than a balancing strategy needs.
    (( count > 1 )) || R_STRATEGY=single
    return 0
}

# Makes sure every DNS name in GTM_RECORDS has addresses; resolves new names now.
# A name that has never resolved fails the save so nothing silently forwards nowhere.
gtm_dns_ensure() {
    local name family list changed=0
    gtm_dns_load || return 1
    while IFS=$'\t' read -r name family; do
        [[ -n $name && -z ${GTM_DNS_ADDR[$name/$family]-} ]] || continue
        list=$(gtm_dns_lookup "$name" "$family" | paste -sd, -)
        [[ -n $list ]] || { gtm_error "Cannot resolve $name to an IPv$family address."; return 1; }
        GTM_DNS_ADDR[$name/$family]=$list; GTM_DNS_CHECKED[$name/$family]=$(date +%s); changed=1
    done < <(gtm_dns_needed)
    ((changed == 0)) || gtm_dns_save
}

# Timer entry point: re-resolves due names, keeps the last good answer on
# failure and reapplies rules and relays only when an address changed.
# Prints "name<TAB>family<TAB>status<TAB>addresses" per name.
gtm_dns_refresh() {
    local force=${1:-} name family list now due every changed=0 result=0 key attempted=0
    local -A needed=() previous_addr=() previous_checked=()
    gtm_prepare && gtm_lock || return 1
    if ! gtm_load_records; then gtm_unlock; return 1; fi
    GTM_DNS_LOADED=''; gtm_dns_load || { gtm_unlock; return 1; }
    for key in "${!GTM_DNS_ADDR[@]}"; do previous_addr[$key]=${GTM_DNS_ADDR[$key]}; previous_checked[$key]=${GTM_DNS_CHECKED[$key]}; done
    [[ ! -e $GTM_DNS_PENDING ]] || changed=1
    now=$(date +%s)
    while IFS=$'\t' read -r name family; do
        [[ -n $name ]] || continue
        needed[$name/$family]=1
        every=${GTM_DNS_EVERY[$name]:-5}
        due=$(( ${GTM_DNS_CHECKED[$name/$family]:-0} + every * 60 ))
        if [[ $force != --force ]] && (( now < due )) && [[ -n ${GTM_DNS_ADDR[$name/$family]-} ]]; then
            printf '%s\t%s\tcached\t%s\n' "$name" "$family" "${GTM_DNS_ADDR[$name/$family]}"; continue
        fi
        list=$(gtm_dns_lookup "$name" "$family" | paste -sd, -)
        if [[ -z $list ]]; then
            printf '%s\t%s\tfailed\t%s\n' "$name" "$family" "${GTM_DNS_ADDR[$name/$family]:--}"; continue
        fi
        GTM_DNS_CHECKED[$name/$family]=$now
        if [[ $list != "${GTM_DNS_ADDR[$name/$family]-}" ]]; then
            GTM_DNS_ADDR[$name/$family]=$list; changed=1
            printf '%s\t%s\tchanged\t%s\n' "$name" "$family" "$list"
        else printf '%s\t%s\tsame\t%s\n' "$name" "$family" "$list"; fi
    done < <(gtm_dns_needed)
    # Forget names no enabled record uses any more.
    for key in "${!GTM_DNS_ADDR[@]}"; do
        [[ ${needed[$key]+set} ]] || { unset 'GTM_DNS_ADDR[$key]' 'GTM_DNS_CHECKED[$key]'; }
    done
    if ((changed)); then
        [[ ! -L $GTM_DNS_PENDING && ( ! -e $GTM_DNS_PENDING || -f $GTM_DNS_PENDING ) ]] && : > "$GTM_DNS_PENDING" || result=1
        # Validate resolved endpoints as well as native syntax before publication.
        if ((result == 0)) && gtm_preflight && gtm_dns_save; then
            attempted=1
            gtm_kernel_apply && gtm_relays_apply || result=1
        else result=1; fi
        if ((result)); then
            GTM_DNS_ADDR=(); GTM_DNS_CHECKED=()
            for key in "${!previous_addr[@]}"; do GTM_DNS_ADDR[$key]=${previous_addr[$key]}; GTM_DNS_CHECKED[$key]=${previous_checked[$key]}; done
            gtm_dns_save || gtm_error 'DNS cache recovery failed; inspect dns-cache.tsv.'
            if ((attempted)); then
                gtm_kernel_apply || gtm_error 'DNS kernel recovery needs attention.'
                gtm_relays_apply || gtm_error 'DNS relay recovery needs attention.'
            fi
            gtm_error 'DNS reconciliation failed; it remains pending for retry.'
        else rm -f "$GTM_DNS_PENDING" || result=1; fi
    else gtm_dns_save || result=1; fi
    gtm_unlock
    return "$result"
}

# Prints the cache and, per enabled record with a DNS name, its resolved
# destinations: "name<TAB>family<TAB>checked<TAB>every<TAB>mode<TAB>addresses"
# and "record<TAB>id<TAB>targets".
gtm_dns_view() {
    local key line
    gtm_load_records && gtm_dns_load || return 1
    for key in "${!GTM_DNS_ADDR[@]}"; do
        printf 'name\t%s\t%s\t%s\t%s\t%s\t%s\n' "${key%/*}" "${key##*/}" "${GTM_DNS_CHECKED[$key]:-0}" "${GTM_DNS_EVERY[${key%/*}]:-5}" "${GTM_DNS_MODE[${key%/*}]:-all}" "${GTM_DNS_ADDR[$key]}"
    done | sort
    for line in "${GTM_RECORDS[@]}"; do
        gtm_record_validate "$line" || return 1
        [[ $R_ENABLED == 1 && $R_TARGETS =~ (^|,)[a-z0-9.-]*[a-z][a-z0-9.-]*: ]] || continue
        if gtm_resolve_targets 2>/dev/null; then printf 'record\t%s\t%s\n' "$R_ID" "$R_TARGETS"; else printf 'record\t%s\t-\n' "$R_ID"; fi
    done
}

# Enables the refresh timer while a record uses a DNS name; removes it otherwise.
gtm_dns_timer_sync() {
    local service="$GTM_SERVICE_DIR/$GTM_DNS_UNIT.service" timer="$GTM_SERVICE_DIR/$GTM_DNS_UNIT.timer" wanted
    wanted=$(gtm_dns_needed) || return 1
    if [[ -z $wanted ]]; then
        [[ -e $timer ]] || return 0
        systemctl disable --now "$GTM_DNS_UNIT.timer" >/dev/null 2>&1 || true
        rm -f "$service" "$timer" && systemctl daemon-reload
        return
    fi
    [[ -e $timer ]] && return 0
    cat > "$service" <<EOF
[Unit]
Description=Traffic Manager domain destination refresh
After=network-online.target
[Service]
Type=oneshot
ExecStart=$GTM_RUNTIME --dns-refresh
EOF
    cat > "$timer" <<EOF
[Unit]
Description=Refresh Traffic Manager domain destinations every minute
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=10s
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload && systemctl enable --now "$GTM_DNS_UNIT.timer" >/dev/null
}
