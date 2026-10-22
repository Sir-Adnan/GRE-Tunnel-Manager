# Fixed terminal styling. No themes, preferences, translations or background fills.
gtm_palette() {
    GTM_RESET=''; GTM_INK=''; GTM_DIM=''; GTM_HIGHLIGHT=''; GTM_BAD=''; GTM_GOOD=''; GTM_RULE=''; GTM_STRONG=''
    BOLD=''; RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; PURPLE=''; WHITE=''; GREY=''; NC=''; HI_CYAN=''; HI_PINK=''; HI_GREEN=''
    [[ -z ${NO_COLOR:-} && ${TERM:-dumb} != dumb && ( -t 1 || ${GTM_FORCE_COLOR:-0} == 1 ) ]] || return 0
    GTM_RESET=$'\033[0m'; GTM_STRONG=$'\033[1m'; GTM_INK=$'\033[0;37m'
    GTM_DIM=$'\033[0;37m'; GTM_HIGHLIGHT=$'\033[0;96m'; GTM_RULE=$'\033[0;36m'
    GTM_BAD=$'\033[0;91m'; GTM_GOOD=$'\033[0;92m'
    BOLD=$GTM_STRONG; RED=$GTM_BAD; GREEN=$GTM_GOOD; YELLOW=$'\033[0;93m'; BLUE=$'\033[0;94m'
    CYAN=$GTM_HIGHLIGHT; PURPLE=$'\033[0;95m'; WHITE=$GTM_INK; GREY=$GTM_DIM
    NC=$GTM_RESET; HI_CYAN=$CYAN; HI_PINK=$PURPLE; HI_GREEN=$GREEN
}

gtm_text() {
    case $1 in
        forward) printf 'Use this server as the entry point.';;
        targets) printf 'Enter a target IP. IP:port is also accepted.';;
        delete) printf 'Select one or more rows, for example: 1 3 4.';;
        confirm) printf 'Check the details before applying.';;
        links) printf 'Use Kharej on one server and Iran on the other.';;
        relay) printf 'This tunnel runs its own service.';;
        reverse) printf 'Set up both servers with the same connection details.';;
        load) printf 'Use several servers for new connections.';;
        haproxy) printf 'TCP tunnel settings. Changes apply only after saving.';;
        tuning) printf 'These settings affect the whole server.';;
        *) printf '%s' "$1";;
    esac
}

gtm_help() { printf '\n  %s\n\n' "$(gtm_text "$1")"; }

gtm_terminal_size() {
    local cols=${COLUMNS:-80} rows=${LINES:-24} measured
    if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
        measured=$(tput cols 2>/dev/null) && cols=$measured
        measured=$(tput lines 2>/dev/null) && rows=$measured
    fi
    gtm_uint "$cols" 20 65535 || cols=80
    gtm_uint "$rows" 10 65535 || rows=24
    GTM_UI_WIDTH=$((cols>84?80:cols-4)); GTM_UI_ROWS=$rows
}

gtm_panel_rule() {
    local line
    printf -v line '%*s' "$GTM_UI_WIDTH" ''
    printf '  %b%s%b\n' "$GTM_RULE" "${line// /-}" "$GTM_RESET"
}

gtm_panel_text() {
    local text=$1 style=${2:-$GTM_INK} room=$GTM_UI_WIDTH
    if ((${#text}>room)); then text="${text:0:room-3}..."; fi
    printf '  %b%s%b\n' "$style" "$text" "$GTM_RESET"
}

gtm_panel_wrap() {
    local text=$1 style=${2:-$GTM_INK} room=$GTM_UI_WIDTH
    while ((${#text}>room)); do gtm_panel_text "${text:0:room}" "$style"; text=${text:room}; done
    gtm_panel_text "$text" "$style"
}

gtm_panel_end() { :; }

gtm_header() {
    local title=$1 brand='GRE TUNNEL MANAGER'
    gtm_terminal_size
    if [[ -t 0 && -t 1 && -n $GTM_RESET ]]; then printf '\033[H\033[2J'; fi
    case $title in HAProxy*|HAPROXY*) brand='H A P R O X Y';; Realm*|REALM*) brand='R E A L M';; FRP*) brand='F R P';; rathole*) brand='R A T H O L E';; esac
    printf '\n'
    gtm_panel_rule
    gtm_panel_text "$brand" "$HI_CYAN$BOLD"
    gtm_panel_text "Tunnel Manager v$GTM_VERSION" "$HI_PINK"
    gtm_panel_rule
    gtm_panel_text "$title" "$BOLD$GTM_INK"
    [[ ${GTM_DEMO:-0} != 1 ]] || printf '  DEMO / no server changes\n'
    printf '\n'
}

gtm_option() {
    local label description=${3:-} room style=$GTM_INK
    case $2 in Add*|Save*|Start*) style=$GREEN;; Delete*|Stop*|Cleanup*) style=$RED;; Back|Cancel|Exit) style=$YELLOW;; esac
    [[ -n ${GTM_UI_WIDTH:-} ]] || gtm_terminal_size
    printf -v label '[%s] %s' "$1" "$2"
    room=$((GTM_UI_WIDTH-29-${#1}))
    if [[ -n $description && $room -ge 25 && ${#2} -le 25 ]]; then
        if ((${#description}>room)); then description="${description:0:room-3}..."; fi
        printf '  %b[%s]%b %-25s %b%s%b\n' "$HI_CYAN" "$1" "$style" "$2" "$GREY" "$description" "$GTM_RESET"
    else gtm_panel_text "$label" "$style"; fi
}

gtm_read() {
    printf '\n  %b%s%b\n  %b>%b ' "$HI_CYAN" "$1" "$GTM_RESET" "$HI_PINK" "$GTM_RESET"
    IFS= read -r "$2"
}

gtm_default() {
    local label=$1 variable=$2 default=$3 _gtm_input
    printf '\n  %b%s%b' "$HI_CYAN" "$label" "$GTM_RESET"
    [[ -z $default ]] || printf '  %b(Enter = %s)%b' "$GREY" "$default" "$GTM_RESET"
    printf '\n  %b>%b ' "$HI_PINK" "$GTM_RESET"
    IFS= read -r _gtm_input || return 1
    printf -v "$variable" '%s' "${_gtm_input:-$default}"
}

# label/value pairs; callers consume GTM_REPLY. No words need to be typed.
gtm_choose() {
    local title=$1 default=$2 entry number=1 selected=1
    local -a labels=() values=()
    shift 2
    while (($#>=2)); do labels+=("$1"); values+=("$2"); shift 2; done
    for entry in "${!values[@]}"; do [[ ${values[$entry]} != "$default" ]] || selected=$((entry+1)); done
    printf '\n  %b%s%b\n' "$HI_PINK$BOLD" "$title" "$GTM_RESET"
    for entry in "${labels[@]}"; do gtm_option "$number" "$entry"; ((number+=1)); done
    gtm_option 0 Cancel
    while true; do
        gtm_default 'Select option' number "$selected" || return 1
        [[ $number != 0 ]] || return 1
        if gtm_uint "$number" 1 "${#values[@]}"; then GTM_REPLY=${values[$((10#$number-1))]}; return 0; fi
        gtm_error 'Choose a number from the menu.'
    done
}

gtm_step() {
    printf '\n  %bSTEP %s/%s  %s%b\n' "$HI_PINK$BOLD" "$1" "$2" "$3" "$GTM_RESET"
    gtm_panel_rule
}

gtm_connection_card() {
    local row=$1 state=$2 target
    [[ -n ${GTM_UI_WIDTH:-} ]] || gtm_terminal_size
    gtm_panel_wrap "[$row] $R_NAME  /  $R_ID" "$HI_CYAN$BOLD"
    gtm_panel_wrap "$R_ENGINE / $R_PROTO / $state" "$GTM_INK"
    gtm_panel_wrap "Local: $(gtm_address "$R_BIND" "$R_PORT")"
    local -a destinations=()
    IFS=, read -r -a destinations <<< "$R_TARGETS"
    for target in "${destinations[@]}"; do
        gtm_endpoint "$target" || return 1
        gtm_panel_wrap "Remote: $(gtm_address "$EP_IP" "$EP_PORT")"
    done
    gtm_panel_rule
}
