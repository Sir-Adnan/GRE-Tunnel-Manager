# Terminal preferences are parsed as data; never sourced as shell code.
gtm_preferences() {
    local key value extra
    GTM_THEME=${GTM_THEME:-dark}; GTM_ACCENT=${GTM_ACCENT:-ocean}; GTM_LANGUAGE=${GTM_LANGUAGE:-en}; GTM_LAYOUT=${GTM_LAYOUT:-guided}
    [[ -r $GTM_PREFS ]] || return 0
    while IFS=$'\t' read -r key value extra; do
        [[ -z $extra ]] || continue
        case "$key:$value" in
            theme:dark|theme:light|theme:plain) GTM_THEME=$value ;;
            accent:ocean|accent:violet|accent:emerald|accent:amber) GTM_ACCENT=$value ;;
            language:en|language:finglish|language:fa) GTM_LANGUAGE=$value ;;
            layout:guided|layout:compact) GTM_LAYOUT=$value ;;
        esac
    done < "$GTM_PREFS"
}

gtm_palette() {
    GTM_RESET=''; GTM_INK=''; GTM_DIM=''; GTM_HIGHLIGHT=''; GTM_BAD=''; GTM_GOOD=''; GTM_RULE=''; GTM_STRONG=''
    BOLD=''; RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; PURPLE=''; WHITE=''; GREY=''; NC=''; HI_CYAN=''; HI_PINK=''; HI_GREEN=''
    [[ ${GTM_THEME:-dark} != plain && -z ${NO_COLOR:-} && ${TERM:-dumb} != dumb && ( -t 1 || ${GTM_FORCE_COLOR:-0} == 1 ) ]] || return 0
    local background foreground muted accent rule bad good colors=8
    if [[ ${TERM:-} == *256color* ]]; then colors=256
    elif command -v tput >/dev/null 2>&1; then colors=$(tput colors 2>/dev/null) || colors=8; fi
    GTM_RESET=$'\033[0m'; GTM_STRONG=$'\033[1m'
    if [[ $colors =~ ^[0-9]+$ ]] && ((colors>=256)); then
        if [[ $GTM_THEME == light ]]; then background=255; foreground=235; muted=240; rule=245; bad=124; good=28
        else background=234; foreground=253; muted=249; rule=241; bad=210; good=114; fi
        case ${GTM_ACCENT:-ocean} in
            violet) accent=183; [[ $GTM_THEME != light ]] || accent=91 ;;
            emerald) accent=115; [[ $GTM_THEME != light ]] || accent=28 ;;
            amber) accent=222; [[ $GTM_THEME != light ]] || accent=130 ;;
            *) accent=81; [[ $GTM_THEME != light ]] || accent=25 ;;
        esac
        printf -v GTM_INK '\033[0;38;5;%s;48;5;%sm' "$foreground" "$background"
        printf -v GTM_DIM '\033[0;38;5;%s;48;5;%sm' "$muted" "$background"
        printf -v GTM_RULE '\033[0;38;5;%s;48;5;%sm' "$rule" "$background"
        printf -v GTM_HIGHLIGHT '\033[0;38;5;%s;48;5;%sm' "$accent" "$background"
        printf -v GTM_BAD '\033[0;38;5;%s;48;5;%sm' "$bad" "$background"
        printf -v GTM_GOOD '\033[0;38;5;%s;48;5;%sm' "$good" "$background"
    else
        if [[ $GTM_THEME == light ]]; then background=47; foreground=30; muted=30; rule=30
        else background=40; foreground=37; muted=37; rule=37; fi
        case ${GTM_ACCENT:-ocean} in violet) accent=35;; emerald) accent=32;; amber) accent=33;; *) accent=36;; esac
        printf -v GTM_INK '\033[0;%s;%sm' "$foreground" "$background"
        printf -v GTM_DIM '\033[0;%s;%sm' "$muted" "$background"
        printf -v GTM_RULE '\033[0;%s;%sm' "$rule" "$background"
        printf -v GTM_HIGHLIGHT '\033[0;%s;%sm' "$accent" "$background"
        printf -v GTM_BAD '\033[0;31;%sm' "$background"
        printf -v GTM_GOOD '\033[0;32;%sm' "$background"
    fi
    BOLD=$GTM_STRONG; RED=$GTM_BAD; GREEN=$GTM_GOOD; YELLOW=$GTM_HIGHLIGHT; BLUE=$GTM_HIGHLIGHT; CYAN=$GTM_HIGHLIGHT
    PURPLE=$GTM_HIGHLIGHT; WHITE=$GTM_INK; GREY=$GTM_DIM; NC=$GTM_RESET; HI_CYAN=$GTM_HIGHLIGHT; HI_PINK=$GTM_HIGHLIGHT; HI_GREEN=$GTM_GOOD
}

gtm_text() {
    local key=$1 lang=${GTM_LANGUAGE:-en}
    case "$key:$lang" in
        welcome:fa) printf 'مدیریت تونل و فوروارد پورت؛ یک بخش را انتخاب کنید.' ;;
        welcome:finglish) printf 'Tunnel ya port forwarding ra entekhab kon.' ;;
        welcome:*) printf 'Choose a tunnel or forward ports.' ;;
        forward:fa) printf 'پورت این سرور و IP و پورت مقصد را وارد کنید.' ;;
        forward:finglish) printf 'Port-e in server va IP:port-e maghsad ra vared kon.' ;;
        forward:*) printf 'Enter this server\047s port and the target IP:port.' ;;
        targets:fa) printf 'هر مقصد را در یک خط وارد کنید. برای پایان، خط خالی وارد کنید.' ;;
        targets:finglish) printf 'Har maghsad ra dar yek khat benevis. Khat-e khali yani payan.' ;;
        targets:*) printf 'One destination per line. Empty line finishes. Example: 10.0.10.1:443@1' ;;
        delete:fa) printf 'شماره‌ها را با فاصله وارد کنید. تمام اجزای فوروارد انتخاب‌شده با هم حذف می‌شوند.' ;;
        delete:finglish) printf 'Shomareha ra ba fasele vared kon. Hameye ajzaye forward-e entekhab-shode ba ham hazf mishavand.' ;;
        delete:*) printf 'Enter row numbers separated by spaces. A forward is removed as one complete group.' ;;
        confirm:fa) printf 'تغییرات را بررسی کنید. فقط منابع متعلق به این مدیر تغییر می‌کنند.\n' ;;
        confirm:finglish) printf 'Taghirat ra barresi kon. Faghat manabe-e moteallegh be in manager taghir mikonand.\n' ;;
        confirm:*) printf 'Review the changes. Only this manager\047s resources are changed.\n' ;;
        links:fa) printf 'اتصال شبکه، مسیر بین سرورها را می‌سازد. انتقال سرویس در بخش فوروارد انجام می‌شود.' ;;
        links:finglish) printf 'Link masir-e beyn-e serverha ra misazad. Enteghal-e service dar Forwarding ast.' ;;
        links:*) printf 'A network link joins servers. Add service ports separately under Forwarding.' ;;
        relay:fa) printf 'رله به سرویس اختیاری نیاز دارد و منابع مصرف می‌کند. انتقال کرنلی سرویس دائمی نمی‌خواهد.' ;;
        relay:finglish) printf 'Relay service-e ekhtiari va masraf-e manabe darad. Forward-e kernel daemon nemikhahad.' ;;
        relay:*) printf 'This method runs its own service.' ;;
        reverse:fa) printf 'سرور مقصد اتصال را به ورودی آغاز می‌کند. راه‌اندازی را روی هر دو سرور انجام دهید و نام و اطلاعات اتصال را یکسان وارد کنید.' ;;
        reverse:finglish) printf 'Server-e maghsad be voroodi vasl mishavad. Har do server ra ba name va etelaat-e yeksan rah-andazi kon.' ;;
        reverse:*) printf 'The destination initiates the connection to the entrance. Configure both servers with matching settings.' ;;
        load:fa) printf 'تقسیم بار برای اتصال‌های جدید است. جابه‌جایی مسیر، حفظ اتصال‌های فعلی را تضمین نمی‌کند.' ;;
        load:finglish) printf 'Load balance baraye connection-haye jadid ast. Taghir-e masir hefz-e connection-haye feli ra tazmin nemikonad.' ;;
        load:*) printf 'Balance new connections across destinations. Failover does not preserve every existing session.' ;;
        haproxy:fa) printf 'این بخش ترافیک TCP را منتقل می‌کند. تنظیمات را مرحله‌ای تغییر دهید و قبل از ارسال اطلاعات کلاینت، پشتیبانی مقصد را بررسی کنید.' ;;
        haproxy:finglish) printf 'In bakhsh traffic-e TCP ra montaghel mikonad. Tanzimat ra marhalei taghir bede; ghabl az PROXY, poshtibani-e maghsad ra barresi kon.' ;;
        haproxy:*) printf 'TCP forwarding. Stage changes, review them, then apply. PROXY metadata needs destination support.' ;;
        tuning:fa) printf 'این تنظیمات روی کل میزبان اثر دارند. مقدار قبلی ثبت می‌شود؛ تغییرات بعدی مدیر سرور در بازگردانی حفظ می‌شوند.' ;;
        tuning:finglish) printf 'In tanzimat rooye kole mizban asar darand. Meghdar-e ghabli sabt mishavad; taghir-e baadi-e admin hefz mishavad.' ;;
        tuning:*) printf 'These settings affect the whole host. Previous values are recorded; later administrator changes are preserved.' ;;
        *) printf '%s' "$key" ;;
    esac
}

gtm_help() {
    gtm_panel_end
    # Guides stay outside fixed-width panels, especially right-to-left Farsi.
    printf '\n  %s\n\n' "$(gtm_text "$1")"
}

# Bound every panel to the current SSH window; tput is optional and read-only.
gtm_terminal_size() {
    local cols=${COLUMNS:-80} rows=${LINES:-24} measured
    if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
        measured=$(tput cols 2>/dev/null) && cols=$measured
        measured=$(tput lines 2>/dev/null) && rows=$measured
    fi
    gtm_uint "$cols" 20 65535 || cols=80
    gtm_uint "$rows" 10 65535 || rows=24
    GTM_UI_WIDTH=$((cols>104?100:cols-4)); GTM_UI_ROWS=$rows
    GTM_UI_TL='+'; GTM_UI_TR='+'; GTM_UI_BL='+'; GTM_UI_BR='+'; GTM_UI_H='-'; GTM_UI_V='|'
    if [[ -n ${GTM_INK:-} && ${LC_ALL:-${LC_CTYPE:-${LANG:-}}} =~ [Uu][Tt][Ff]-?8 ]]; then
        GTM_UI_TL='╭'; GTM_UI_TR='╮'; GTM_UI_BL='╰'; GTM_UI_BR='╯'; GTM_UI_H='─'; GTM_UI_V='│'
    fi
}

gtm_panel_rule() {
    local side=${1:-top} left=$GTM_UI_TL right=$GTM_UI_TR line
    [[ $side != bottom ]] || { left=$GTM_UI_BL; right=$GTM_UI_BR; }
    printf -v line '%*s' "$((GTM_UI_WIDTH-2))" ''
    line=${line// /$GTM_UI_H}
    printf '  %b%s%s%s%b\n' "$GTM_RULE" "$left" "$line" "$right" "$GTM_RESET"
}

gtm_panel_text() {
    local text=$1 style=${2:-$GTM_INK} room=$((GTM_UI_WIDTH-4))
    if ((${#text}>room)); then text="${text:0:room-3}..."; fi
    printf '  %b%s %b%-*s%b %s%b\n' "$GTM_RULE" "$GTM_UI_V" "$style" "$room" "$text" "$GTM_RULE" "$GTM_UI_V" "$GTM_RESET"
}

# Wrap technical data without dropping an address, port, ID or destination.
gtm_panel_wrap() {
    local text=$1 style=${2:-$GTM_INK} room=$((GTM_UI_WIDTH-4))
    while ((${#text}>room)); do
        gtm_panel_text "${text:0:room}" "$style"
        text=${text:room}
    done
    gtm_panel_text "$text" "$style"
}

gtm_connection_card() {
    local row=$1 state=$2 target style=$GTM_DIM
    gtm_panel_end
    [[ -n ${GTM_UI_WIDTH:-} ]] || gtm_terminal_size
    [[ $R_ENABLED != 1 ]] || style=$GTM_GOOD
    gtm_panel_rule
    gtm_panel_wrap "[$row] $R_NAME" "$GTM_HIGHLIGHT$GTM_STRONG"
    gtm_panel_wrap "$R_ID / $R_ENGINE / $R_PROTO / $state" "$style"
    gtm_panel_wrap "Listen: $(gtm_address "$R_BIND" "$R_PORT")"
    local -a destinations=()
    IFS=, read -r -a destinations <<< "$R_TARGETS"
    for target in "${destinations[@]}"; do gtm_panel_wrap "Target: $target"; done
    gtm_panel_wrap "Balance: $R_STRATEGY / Source: $R_SNAT" "$GTM_DIM"
    gtm_panel_rule bottom
}

gtm_panel_end() {
    if [[ ${GTM_PANEL_OPEN:-0} == 1 ]]; then gtm_panel_rule bottom; fi
    GTM_PANEL_OPEN=0
}

gtm_header() {
    local title=$1
    gtm_panel_end; gtm_terminal_size
    printf '\n'
    gtm_panel_rule
    gtm_panel_text "GRE TUNNEL MANAGER   /   v$GTM_VERSION" "$GTM_HIGHLIGHT$GTM_STRONG"
    gtm_panel_text "$title"
    gtm_panel_rule bottom
    [[ ${GTM_DEMO:-0} == 1 ]] && printf '  DEMO: sample data; server changes are disabled.\n'
    return 0
}

gtm_option() {
    local label key=$1 title=$2 description=${3:-} room
    [[ ${GTM_LAYOUT:-guided} != compact ]] || description=''
    [[ -n ${GTM_UI_WIDTH:-} ]] || gtm_terminal_size
    room=$((GTM_UI_WIDTH-4))
    if [[ ${GTM_PANEL_OPEN:-0} != 1 ]]; then gtm_panel_rule; GTM_PANEL_OPEN=1; fi
    printf -v label '[%s] %-23s' "$key" "$title"
    if [[ -n $description ]]; then
        if ((room>=68)); then
            # Style each cell without allowing the terminal background to leak through.
            local remaining=$((room-${#label}-2))
            if ((remaining<3)); then label="${label:0:room-8}..."; remaining=3; fi
            if ((${#description}>remaining)); then description="${description:0:remaining-3}..."; fi
            printf '  %b%s %b%s%b  %-*s%b %s%b\n' "$GTM_RULE" "$GTM_UI_V" "$GTM_HIGHLIGHT" "$label" "$GTM_DIM" "$remaining" "$description" "$GTM_RULE" "$GTM_UI_V" "$GTM_RESET"
            return
        fi
    fi
    gtm_panel_text "[$key] $title" "$GTM_HIGHLIGHT"
    if [[ -n $description && ${GTM_LAYOUT:-guided} == guided && $GTM_UI_ROWS -ge 32 ]]; then
        gtm_panel_text "    $description" "$GTM_DIM"
    fi
}
gtm_read() { gtm_panel_end; printf '\n  %b%b%s%b' "$GTM_HIGHLIGHT" "$GTM_STRONG" "$1" "$GTM_RESET"; IFS= read -r "$2"; }

gtm_default() {
    local label=$1 variable=$2 default=$3 answer
    gtm_panel_end
    printf '\n  %s' "$label"
    [[ -z $default ]] || printf ' [%s]' "$default"
    printf ': '
    IFS= read -r answer || return 1
    printf -v "$variable" '%s' "${answer:-$default}"
}

gtm_settings() {
    local choice value
    while true; do
        gtm_header 'Appearance & help'
        printf '  Theme: %s | Accent: %s | Help: %s | Layout: %s\n\n' "$GTM_THEME" "$GTM_ACCENT" "$GTM_LANGUAGE" "$GTM_LAYOUT"
        gtm_option 1 'Theme' 'dark / light / plain'
        gtm_option 2 'Accent' 'ocean / violet / emerald / amber'
        gtm_option 3 'Help language' 'English / Finglish / Farsi'
        gtm_option 4 'Test Farsi display' 'Read before enabling Farsi help'
        gtm_option 5 'Layout' 'guided / compact'
        gtm_option 0 Back
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_read 'Theme: ' value || return; case $value in dark|light|plain) GTM_THEME=$value;; *) continue;; esac ;;
            2) gtm_read 'Accent: ' value || return; case $value in ocean|violet|emerald|amber) GTM_ACCENT=$value;; *) continue;; esac ;;
            3) gtm_read 'Help [en/finglish/fa]: ' value || return; case $value in en|finglish|fa) GTM_LANGUAGE=$value;; *) continue;; esac ;;
            4) printf '\nفارسی: اگر حروف این جمله پیوسته و خوانا هستند، راهنمای فارسی را انتخاب کنید.\n\nIP: 10.0.10.1\nPort: 443\nCommand: ip link show\n\nIf letters are separated or reversed, use English or Finglish.\n'; gtm_pause; continue ;;
            5) gtm_read 'Layout [guided/compact]: ' value || return; case $value in guided|compact) GTM_LAYOUT=$value;; *) continue;; esac ;;
            0) return ;; *) continue ;;
        esac
        gtm_palette
        if [[ ${GTM_DEMO:-0} == 0 ]]; then
            gtm_prepare && gtm_lock || return
            { printf 'theme\t%s\naccent\t%s\nlanguage\t%s\nlayout\t%s\n' "$GTM_THEME" "$GTM_ACCENT" "$GTM_LANGUAGE" "$GTM_LAYOUT" > "$GTM_PREFS.tmp" && mv "$GTM_PREFS.tmp" "$GTM_PREFS"; } || gtm_error 'Could not save preferences.'
            gtm_unlock
        fi
    done
}
