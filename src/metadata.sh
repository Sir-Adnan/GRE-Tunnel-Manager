# Optional display names. Callers hold the existing manager lock for all writes.
# Technical unit names, peer keys and tunnel addresses never change.
gtm_metadata_id() { [[ $1 =~ ^(gre-tun-([1-9][0-9]{0,2})|gtm-(frp|rathole)-(entrance|destination)-[a-zA-Z0-9_-]{1,32})$ ]]; }
gtm_metadata_load() {
    local file="$GTM_CONFIG_DIR/resource-names.tsv" line id fingerprint name extra
    local -A seen=()
    GTM_METADATA=()
    [[ -e $file || -L $file ]] || return 0
    [[ -f $file && ! -L $file && $(stat -c %s "$file") -le 131072 ]] || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        extra=${line//[^$'\t']/}; ((${#extra}==2)) || return 1
        IFS=$'\t' read -r id fingerprint name <<< "$line"
        gtm_metadata_id "$id" && [[ $fingerprint =~ ^[a-f0-9]{64}$ ]] && gtm_name "$name" && [[ ! ${seen[$id]+set} ]] || return 1
        seen[$id]=1; GTM_METADATA+=("$line")
        ((${#GTM_METADATA[@]}<=512)) || return 1
    done < "$file"
}
gtm_metadata_save() {
    local file="$GTM_CONFIG_DIR/resource-names.tsv" tmp
    tmp=$(mktemp "$GTM_CONFIG_DIR/names.XXXXXX") || return 1
    if ((${#GTM_METADATA[@]})); then printf '%s\n' "${GTM_METADATA[@]}" > "$tmp" || { rm -f "$tmp"; return 1; }; fi
    if [[ -f $file ]]; then
        [[ ! -L $file.bak && ( ! -e $file.bak || -f $file.bak ) ]] && cp -p "$file" "$file.bak" || { rm -f "$tmp"; return 1; }
    fi
    chmod 600 "$tmp" && mv "$tmp" "$file" || { rm -f "$tmp"; return 1; }
}
gtm_metadata_forget() {
    local id=$1 line
    local -a kept=()
    gtm_metadata_load || return 1
    for line in "${GTM_METADATA[@]}"; do [[ ${line%%$'\t'*} == "$id" ]] || kept+=("$line"); done
    ((${#kept[@]}!=${#GTM_METADATA[@]})) || return 0
    GTM_METADATA=("${kept[@]}"); gtm_metadata_save
}
gtm_metadata_rename() {
    local id=$1 revision=$2 name=$3 file="$GTM_SERVICE_DIR/$1.service" unit_hash row_hash='-' line existing='' hash
    local -a kept=()
    gtm_metadata_id "$id" && [[ $revision =~ ^[a-f0-9]{64}:([a-f0-9]{64}|-)$ ]] && { [[ $name == - ]] || gtm_name "$name"; } || return 1
    [[ -f $file && ! -L $file ]] && gtm_metadata_load || return 1
    unit_hash=$(sha256sum "$file") || return 1; unit_hash=${unit_hash%% *}
    for line in "${GTM_METADATA[@]}"; do
        if [[ ${line%%$'\t'*} == "$id" ]]; then existing=$line; else kept+=("$line"); fi
    done
    if [[ -n $existing ]]; then hash=$(printf '%s' "$existing" | sha256sum) || return 1; row_hash=${hash%% *}; fi
    [[ $revision == "$unit_hash:$row_hash" ]] || { gtm_error 'Display name changed; refresh and try again.'; return 1; }
    [[ $name == - ]] || kept+=("$id"$'\t'"$unit_hash"$'\t'"$name")
    ((${#kept[@]}<=512)) || return 1
    GTM_METADATA=("${kept[@]}"); gtm_metadata_save
}
