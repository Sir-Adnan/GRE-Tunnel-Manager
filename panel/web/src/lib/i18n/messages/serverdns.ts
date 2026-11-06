// Optimization → DNS, the safe-apply banner and the Port Forward Manager import.
import type { Messages } from "./types";

export const serverdns = {
  dnsConfiguredServers: ["Configured by this manager", "تنظیم‌شده توسط مدیر"],
  dnsActiveGlobal: ["Active global resolvers", "DNSهای عمومی فعال سیستم"],
  dnsStubHelp: [
    "The local stub address can stay 127.0.0.53. DHCP resolvers may still appear in the upstream file; the global routing policy selects the configured servers for ordinary domains.",
    "آدرس resolver محلی ممکن است همچنان 127.0.0.53 باشد. DNSهای DHCP نیز ممکن است در فایل upstream بمانند؛ سیاست مسیریابی عمومی، سرورهای انتخابی را برای دامنه‌های معمول به کار می‌گیرد.",
  ],
  optimizeTabs: ["Optimization sections", "بخش‌های بهینه‌سازی"],
  optimizeTabPerformance: ["Performance", "کارایی"],
  optimizeTabDNS: ["DNS", "DNS"],

  dnsCurrent: ["This server's DNS", "DNS این سرور"],
  dnsMode_resolved: [
    "systemd-resolved: global servers through a drop-in",
    "سرورهای سراسری در systemd-resolved، با یک فایل drop-in",
  ],
  dnsMode_file: [
    "/etc/resolv.conf, written again at boot",
    "فایل /etc/resolv.conf، که هنگام بوت دوباره نوشته می‌شود",
  ],
  dnsMode_resolvconf: ["Managed by resolvconf", "مدیریت‌شده با resolvconf"],
  dnsMode_networkmanager: [
    "Managed by NetworkManager",
    "مدیریت‌شده با NetworkManager",
  ],
  dnsMode_unknown: ["Unknown resolver setup", "پیکربندی resolver ناشناخته"],
  dnsManaged: ["Set from this panel", "تنظیم‌شده از همین پنل"],
  dnsNotManaged: [
    "These are the server's own settings; the panel has not changed them.",
    "این‌ها تنظیمات خود سرور است و پنل تغییرشان نداده.",
  ],
  dnsOriginal: ["Original", "مقدار اصلی"],
  dnsOriginalUnknown: ["the server's previous settings", "تنظیمات قبلی سرور"],
  dnsUnsupported_resolvconf: [
    "DNS here is managed by resolvconf. Change it in /etc/resolvconf so it is not overwritten.",
    "DNS این سرور با resolvconf مدیریت می‌شود. آن را در /etc/resolvconf تغییر دهید تا بازنویسی نشود.",
  ],
  dnsUnsupported_networkmanager: [
    "DNS here is managed by NetworkManager. Change it with nmcli so it is not overwritten.",
    "DNS این سرور با NetworkManager مدیریت می‌شود. با nmcli تغییرش دهید تا بازنویسی نشود.",
  ],
  dnsUnsupported_unknown: [
    "The resolver setup could not be recognized, so nothing will be changed.",
    "پیکربندی resolver شناخته نشد، پس چیزی تغییر نمی‌کند.",
  ],
  dnsPersistHelp: [
    "Survives reboots and DHCP renewals. Restore puts back exactly what the server had.",
    "بعد از ریبوت و تمدید DHCP هم می‌ماند. «بازگردانی» دقیقاً همان تنظیمات قبلی سرور را برمی‌گرداند.",
  ],
  dnsChoose: ["Choose servers", "انتخاب سرورها"],
  dnsChooseHelp: [
    "The speed test runs from this server: three lookups per server, median time.",
    "تست سرعت از همین سرور اجرا می‌شود: سه پرس‌وجو برای هر سرور، زمان میانه.",
  ],
  dnsGroupGlobal: ["International", "بین‌المللی"],
  dnsGroupIran: ["Iran", "ایران"],
  dnsGroupManual: ["Manual", "دستی"],
  dnsIranHelp: [
    "Iranian resolvers help reach services that block Iranian addresses (anti-sanction DNS). Some only answer from inside Iran.",
    "DNSهای ایرانی برای دسترسی به سرویس‌هایی که آی‌پی ایران را مسدود می‌کنند (ضدتحریم) کمک می‌کنند. بعضی فقط از داخل ایران پاسخ می‌دهند.",
  ],
  dnsTestAll: ["Test all", "تست همه"],
  dnsTestThese: ["Test these", "تست این‌ها"],
  dnsTesting: ["Testing…", "در حال تست…"],
  dnsTestFailed: ["No answer", "بدون پاسخ"],
  dnsFastest: ["Fastest", "سریع‌ترین"],
  dnsInUse: ["In use", "در حال استفاده"],
  dnsAddIPv6: ["Also add the IPv6 servers", "سرورهای IPv6 هم اضافه شوند"],
  dnsManualLabel: ["DNS servers (one to four)", "سرورهای DNS (یک تا چهار)"],
  dnsManualHelp: [
    "IPv4 or IPv6, one per line or separated by spaces.",
    "IPv4 یا IPv6، هر خط یکی یا با فاصله جدا شده.",
  ],
  dnsManualBad: [
    "Not usable as a DNS server: {s}",
    "به‌عنوان DNS قابل استفاده نیست: {s}",
  ],
  dnsManualTooMany: ["Use at most four servers.", "حداکثر چهار سرور."],
  dnsWillUse: ["Will use", "استفاده خواهد شد:"],
  dnsPickOne: [
    "Pick a provider or enter servers.",
    "یک ارائه‌دهنده انتخاب کنید یا سرورها را وارد کنید.",
  ],
  dnsApply: ["Apply DNS", "اعمال DNS"],
  dnsApplyTitle: ["Change this server's DNS?", "DNS این سرور تغییر کند؟"],
  dnsApplyResolved: [
    "systemd-resolved will use {s} for every domain and restart (a second without DNS). Connections already open are not affected.",
    "systemd-resolved برای همهٔ دامنه‌ها از {s} استفاده می‌کند و دوباره راه‌اندازی می‌شود (حدود یک ثانیه بدون DNS). اتصال‌های باز تحت تأثیر قرار نمی‌گیرند.",
  ],
  dnsApplyFile: [
    "/etc/resolv.conf will list {s} (search and options lines are kept) and a small boot unit writes it again after DHCP.",
    "‏/etc/resolv.conf شامل {s} می‌شود (خط‌های search و options حفظ می‌شوند) و یک سرویس کوچک بوت، آن را بعد از DHCP دوباره می‌نویسد.",
  ],
  dnsRestore: ["Restore original", "بازگردانی تنظیمات اصلی"],
  dnsRestoreTitle: ["Restore the original DNS?", "DNS اصلی بازگردانده شود؟"],
  dnsRestoreBody: [
    "The server goes back to {s} and the panel's DNS files are removed.",
    "سرور به {s} برمی‌گردد و فایل‌های DNS پنل حذف می‌شوند.",
  ],
  msValue: ["{n} ms", "{n} میلی‌ثانیه"],
  loading: ["Loading…", "در حال بارگذاری…"],

  safeBannerTitle: [
    "Unconfirmed change — reverts in {t}:",
    "تغییر تأییدنشده — برگشت در {t}:",
  ],
  safeAction_create: ["New connection", "اتصال جدید"],
  safeAction_update: ["Edited connection", "ویرایش اتصال"],
  safeAction_delete: ["Deleted connections", "حذف اتصال"],
  safeAction_enable: ["Started connections", "روشن کردن اتصال"],
  safeAction_disable: ["Stopped connections", "خاموش کردن اتصال"],
  safeBannerKeep: ["Keep changes", "نگه داشتن تغییرات"],
  safeBannerRevert: ["Revert now", "برگرداندن الان"],

  importPortfw: [
    "Port Forward Manager (this server)",
    "Port Forward Manager (همین سرور)",
  ],
  importPortfwHelp: [
    "Reads the saved rules of Port Forward Manager (portfw / portfw-nft) on this server: ranges stay one rule, mapped ports and domains are kept. Nothing of portfw is changed; remove its rules after importing.",
    "قوانین ذخیره‌شدهٔ Port Forward Manager (portfw / portfw-nft) روی همین سرور خوانده می‌شود: بازه‌ها یک قانون می‌مانند و نگاشت پورت‌ها و دامنه‌ها حفظ می‌شوند. چیزی از portfw تغییر نمی‌کند؛ بعد از وارد کردن، قوانین آن را حذف کنید.",
  ],
  importPortfwIptables: [
    "Rules that map to other port numbers need nftables.",
    "قوانینی که به شماره‌پورت دیگری نگاشت می‌شوند به nftables نیاز دارند.",
  ],
} satisfies Messages;
