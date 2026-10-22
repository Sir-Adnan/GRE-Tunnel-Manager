# Terminal preferences are parsed as data; never sourced as shell code.
gtm_preferences() {
    local key value extra
    GTM_THEME=${GTM_THEME:-dark}; GTM_ACCENT=${GTM_ACCENT:-ocean}; GTM_LANGUAGE=${GTM_LANGUAGE:-en}
    [[ -r $GTM_PREFS ]] || return 0
    while IFS=$'\t' read -r key value extra; do
        [[ -z $extra ]] || continue
        case "$key:$value" in
            theme:dark|theme:light|theme:plain) GTM_THEME=$value ;;
            accent:ocean|accent:violet|accent:emerald|accent:amber) GTM_ACCENT=$value ;;
            language:en|language:finglish|language:fa) GTM_LANGUAGE=$value ;;
        esac
    done < "$GTM_PREFS"
}

gtm_palette() {
    GTM_RESET=''; GTM_INK=''; GTM_DIM=''; GTM_HIGHLIGHT=''; GTM_BAD=''; GTM_GOOD=''
    BOLD=''; RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; PURPLE=''; WHITE=''; GREY=''; NC=''; HI_CYAN=''; HI_PINK=''; HI_GREEN=''
    [[ ${GTM_THEME:-dark} != plain && -z ${NO_COLOR:-} && ${TERM:-dumb} != dumb && ( -t 1 || ${GTM_FORCE_COLOR:-0} == 1 ) ]] || return 0
    GTM_RESET=$'\033[0m'; GTM_BAD=$'\033[31m'; GTM_GOOD=$'\033[32m'
    if [[ $GTM_THEME == light ]]; then GTM_INK=$'\033[30;47m'; GTM_DIM=$'\033[90;47m'
    else GTM_INK=$'\033[37;40m'; GTM_DIM=$'\033[90;40m'; fi
    case ${GTM_ACCENT:-ocean} in
        violet) GTM_HIGHLIGHT=$'\033[35m' ;; emerald) GTM_HIGHLIGHT=$'\033[32m' ;;
        amber) GTM_HIGHLIGHT=$'\033[33m' ;; *) GTM_HIGHLIGHT=$'\033[36m' ;;
    esac
    BOLD=$GTM_INK; RED=$GTM_BAD; GREEN=$GTM_GOOD; YELLOW=$GTM_HIGHLIGHT; BLUE=$GTM_HIGHLIGHT; CYAN=$GTM_HIGHLIGHT
    PURPLE=$GTM_HIGHLIGHT; WHITE=$GTM_INK; GREY=$GTM_DIM; NC=$GTM_RESET; HI_CYAN=$GTM_HIGHLIGHT; HI_PINK=$GTM_HIGHLIGHT; HI_GREEN=$GTM_GOOD
}

gtm_text() {
    local key=$1 lang=${GTM_LANGUAGE:-en}
    case "$key:$lang" in
        welcome:fa) printf 'مدیریت ارتباط و انتقال ترافیک بین سرورها' ;;
        welcome:finglish) printf 'Modiriat-e ertebat va enteghal-e traffic beyn-e serverha' ;;
        welcome:*) printf 'Connect servers. Move traffic. Keep control.' ;;
        forward:fa) printf 'پورت ورودی و مقصد را انتخاب کنید. مقصد می‌تواند عمومی یا داخل یک اتصال باشد.' ;;
        forward:finglish) printf 'Port-e voroodi va maghsad ra entekhab kon. Maghsad mitavanad IP omoomi ya dakheli bashad.' ;;
        forward:*) printf 'Choose an entrance port and destination. Use a public or private tunnel address.' ;;
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
        relay:*) printf 'Relays run optional services. Kernel forwarding adds no resident manager.' ;;
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

gtm_help() { printf '\n  %b%s%b\n\n' "$GTM_DIM" "$(gtm_text "$1")" "$GTM_RESET"; }

gtm_header() {
    local title=$1 cols=${COLUMNS:-80} width
    gtm_uint "$cols" 20 65535 || cols=80
    width=$((cols<76?cols:76))
    printf '\n%b  TRAFFIC MANAGER  /  v%s%b\n' "$GTM_HIGHLIGHT" "$GTM_VERSION" "$GTM_RESET"
    printf '  %s\n' "$title"
    printf '%*s\n' "$width" '' | tr ' ' '-'
    [[ ${GTM_DEMO:-0} == 1 ]] && printf '  DEMO: sample data; server changes are disabled.\n'
    return 0
}

gtm_option() {
    local cols=${COLUMNS:-80}
    gtm_uint "$cols" 20 65535 || cols=80
    printf '%b  %b[%s]%b %s' "$GTM_INK" "$GTM_HIGHLIGHT" "$1" "$GTM_INK" "$2"
    if [[ -n ${3:-} ]]; then
        if ((cols<76)); then printf '\n      %b%s' "$GTM_DIM" "$3"; else printf '  %b- %s' "$GTM_DIM" "$3"; fi
    fi
    printf '%b\n' "$GTM_RESET"
}
gtm_read() { printf '\n  %s' "$1"; IFS= read -r "$2"; }

gtm_default() {
    local label=$1 variable=$2 default=$3 answer
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
        printf '  Theme: %s | Accent: %s | Help: %s\n\n' "$GTM_THEME" "$GTM_ACCENT" "$GTM_LANGUAGE"
        gtm_option 1 'Theme' 'dark / light / plain'
        gtm_option 2 'Accent' 'ocean / violet / emerald / amber'
        gtm_option 3 'Help language' 'English / Finglish / Farsi'
        gtm_option 4 'Test Farsi display' 'Read before enabling Farsi help'
        gtm_option 0 Back
        gtm_read 'Choose: ' choice || return
        case $choice in
            1) gtm_read 'Theme: ' value || return; case $value in dark|light|plain) GTM_THEME=$value;; *) continue;; esac ;;
            2) gtm_read 'Accent: ' value || return; case $value in ocean|violet|emerald|amber) GTM_ACCENT=$value;; *) continue;; esac ;;
            3) gtm_read 'Help [en/finglish/fa]: ' value || return; case $value in en|finglish|fa) GTM_LANGUAGE=$value;; *) continue;; esac ;;
            4) printf '\nفارسی: اگر حروف این جمله پیوسته و خوانا هستند، راهنمای فارسی را انتخاب کنید.\n\nIP: 10.0.10.1\nPort: 443\nCommand: ip link show\n\nIf letters are separated or reversed, use English or Finglish.\n'; gtm_pause; continue ;;
            0) return ;; *) continue ;;
        esac
        gtm_palette
        if [[ ${GTM_DEMO:-0} == 0 ]]; then
            gtm_prepare && gtm_lock || return
            { printf 'theme\t%s\naccent\t%s\nlanguage\t%s\n' "$GTM_THEME" "$GTM_ACCENT" "$GTM_LANGUAGE" > "$GTM_PREFS.tmp" && mv "$GTM_PREFS.tmp" "$GTM_PREFS"; } || gtm_error 'Could not save preferences.'
            gtm_unlock
        fi
    done
}
