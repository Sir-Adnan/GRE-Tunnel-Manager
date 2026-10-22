# Noninteractive control boundary. Input is validated TSV data, never shell code.
# The privileged local broker is the only web-panel caller; the CLI can use it too.
gtm_api_rows() {
    local line id component result=1 count=0
    local -a incoming=()
    while IFS= read -r line || [[ -n $line ]]; do
        ((count+=1)); ((count<=32)) && gtm_record_validate "$line" && [[ $R_ID == F000000 ]] || return 1
        incoming+=("$line")
    done
    ((count>0)) && gtm_prepare && gtm_lock || return 1
    if ! gtm_load_records; then gtm_unlock; return 1; fi
    for line in "${incoming[@]}"; do
        gtm_record_validate "$line" || { gtm_unlock; return 1; }
        component=$R_ENGINE
        case $component in iptables) gtm_need iptables;; nftables) gtm_need nft;; *) gtm_need "$component";; esac || { gtm_unlock; return 1; }
        if [[ $R_ENABLED == 1 ]]; then
            gtm_listener_check "$R_PROTO" "$R_BIND" "$R_PORT" && gtm_legacy_listener_check "$R_PROTO" "$R_BIND" "$R_PORT" || { gtm_unlock; return 1; }
        fi
        id=$(gtm_new_id) || { gtm_unlock; return 1; }
        GTM_RECORDS+=("$id${line#F000000}")
    done
    printf '%d\n' "$((10#${id#F}))" > "$GTM_CONFIG_DIR/id-counter.tmp" && mv "$GTM_CONFIG_DIR/id-counter.tmp" "$GTM_CONFIG_DIR/id-counter" || { gtm_unlock; return 1; }
    gtm_commit; result=$?
    gtm_unlock
    return "$result"
}

gtm_api_change() {
    local operation=$1 expected replacement='' line result=1 found=0 previous_bind previous_port previous_proto previous_enabled
    local -a originals=() updated=()
    while IFS= read -r line || [[ -n $line ]]; do
        gtm_record_validate "$line" && [[ $R_ID != F000000 ]] || return 1
        originals+=("$line"); ((${#originals[@]}<=128)) || return 1
    done
    if [[ $operation == update ]]; then
        ((${#originals[@]}==2)) && [[ ${originals[0]%%$'\t'*} == "${originals[1]%%$'\t'*}" ]] || return 1
        replacement=${originals[1]}; originals=("${originals[0]}")
    fi
    ((${#originals[@]}>0)) && gtm_prepare && gtm_lock || return 1
    if ! gtm_load_records; then gtm_unlock; return 1; fi
    # Verify every selected row before mutating anything, including bulk operations.
    for expected in "${originals[@]}"; do
        found=0
        for line in "${GTM_RECORDS[@]}"; do [[ $line != "$expected" ]] || found=1; done
        ((found)) || { gtm_error 'Connection changed; refresh and try again.'; gtm_unlock; return 1; }
    done
    for line in "${GTM_RECORDS[@]}"; do
        found=0
        for expected in "${originals[@]}"; do [[ $line != "$expected" ]] || found=1; done
        if ((found)); then
            gtm_record_validate "$line" || { gtm_unlock; return 1; }
            previous_bind=$R_BIND; previous_port=$R_PORT; previous_proto=$R_PROTO; previous_enabled=$R_ENABLED
            case $operation in
                delete) continue;;
                update) line=$replacement;;
                enable|disable)
                    gtm_record_validate "$line" || { gtm_unlock; return 1; }
                    R_ENABLED=0; [[ $operation != enable ]] || R_ENABLED=1
                    line=$(gtm_record_emit);;
                *) gtm_unlock; return 1;;
            esac
            gtm_record_validate "$line" || { gtm_unlock; return 1; }
            if [[ $R_ENABLED == 1 && ( $previous_enabled == 0 || $R_BIND != "$previous_bind" || $R_PORT != "$previous_port" || $R_PROTO != "$previous_proto" ) ]]; then
                gtm_listener_check "$R_PROTO" "$R_BIND" "$R_PORT" && gtm_legacy_listener_check "$R_PROTO" "$R_BIND" "$R_PORT" || { gtm_unlock; return 1; }
            fi
        fi
        updated+=("$line")
    done
    GTM_RECORDS=("${updated[@]}")
    gtm_commit; result=$?
    gtm_unlock
    return "$result"
}

gtm_api() {
    local operation=${1:-} component
    shift || return 2
    case $operation in
        state) (($#==0)) && gtm_load_records && { ((${#GTM_RECORDS[@]}==0)) || printf '%s\n' "${GTM_RECORDS[@]}"; };;
        create) (($#==0)) && gtm_api_rows;;
        update|enable|disable|delete) (($#==0)) && gtm_api_change "$operation";;
        plan) (($#==0)) && gtm_plan;;
        doctor) (($#==0)) && gtm_doctor;;
        install)
            (($#>0 && $#<=7)) && gtm_prepare || return 2
            for component in "$@"; do
                case $component in iptables|nftables|haproxy|realm|frp|rathole) ;; *) return 2;; esac
            done
            # Explicit --api install authorizes these specific packages. No service
            # is enabled by this boundary; engine units are created only on apply.
            gtm_confirm() { return 0; }
            for component in "$@"; do gtm_install_component "$component" || return 1; done;;
        gre-create) (($#==5)) && gtm_prepare && gtm_lock || return 2
            gtm_link_create "$@"; local result=$?; gtm_unlock; return "$result";;
        gre-delete) (($#==1)) && gtm_prepare && gtm_lock || return 2
            gtm_confirm() { return 0; }
            gtm_link_delete "$1"; local result=$?; gtm_unlock; return "$result";;
        reverse-create) (($#==0)) && gtm_api_reverse;;
        reverse-delete) (($#==1)) && gtm_prepare && gtm_lock || return 2
            gtm_reverse_delete "$1"; local result=$?; gtm_unlock; return "$result";;
        *) gtm_error 'Unknown API operation.'; return 2;;
    esac
}
