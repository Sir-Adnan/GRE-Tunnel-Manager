// Firewall page: host firewall status, ports and UFW, per-connection access
// rules, abuse protection and the automatic revert of unconfirmed changes.
import type { Messages } from "./types";

export const firewall = {
  firewall: ["Firewall", "فایروال"],
  fwIntro: [
    "See how this server's firewall treats your connections, open their ports in UFW, limit who may use each one and stop abuse reports. Only the manager's own rules change.",
    "ببینید فایروال این سرور با اتصال‌های شما چه می‌کند. پورت‌ها را در UFW باز کنید، مشخص کنید چه کسانی از هر اتصال استفاده کنند و جلوی گزارش abuse را بگیرید. فقط قوانین خود برنامه تغییر می‌کنند.",
  ],
  fwLoadFailed: [
    "The firewall report could not be read.",
    "گزارش فایروال خوانده نشد.",
  ],

  // Attention
  fwAttention: ["Needs attention", "نیاز به توجه"],
  fwAllClear: [
    "Nothing in the firewall blocks your connections.",
    "چیزی در فایروال جلوی اتصال‌های شما را نمی‌گیرد.",
  ],
  fwGuardMissing: [
    "{tool} drops forwarded traffic and the manager's accept rule is missing there, so kernel forwards (nftables/iptables) of IPv{f} are blocked.",
    "{tool} ترافیک عبوری را رد می‌کند و قانون اجازه‌ی برنامه آنجا نیست، پس اتصال‌های کرنل (nftables/iptables) روی IPv{f} مسدود هستند.",
  ],
  fwGuardFix: [
    "Reapply the kernel rules; the accept goes into every backend that drops.",
    "قوانین کرنل را دوباره اعمال کنید؛ قانون اجازه در هر بک‌اندی که ترافیک را رد می‌کند قرار می‌گیرد.",
  ],
  fwNotApplied: [
    "Your firewall settings are saved but not loaded in the kernel.",
    "تنظیمات فایروال ذخیره شده ولی در کرنل بارگذاری نشده است.",
  ],
  fwNoNft: [
    "nftables is not installed; access rules and abuse protection need it.",
    "nftables نصب نیست؛ قوانین دسترسی و جلوگیری از abuse به آن نیاز دارند.",
  ],
  fwRelayClosed: [
    "UFW blocks incoming traffic and port {p} of {n} is not open.",
    "UFW ترافیک ورودی را مسدود می‌کند و پورت {p} اتصال {n} باز نیست.",
  ],
  fwRelayClosedFix: [
    "Turn on “Open in UFW” for this connection below.",
    "برای این اتصال، گزینه‌ی «باز در UFW» را در پایین روشن کنید.",
  ],
  fwFirewalld: [
    "firewalld is active. Its own rules may still drop forwarded traffic; allow the ports there too.",
    "firewalld فعال است. ممکن است قوانین خودش همچنان ترافیک عبوری را رد کنند؛ پورت‌ها را آنجا هم مجاز کنید.",
  ],
  fwRepair: ["Fix now", "رفع"],
  fwRepairDone: ["Kernel rules reapplied.", "قوانین کرنل دوباره اعمال شدند."],

  // Status tiles
  fwStatus: ["Firewall status", "وضعیت فایروال"],
  fwUFW: ["UFW", "UFW"],
  fwUFW_active: ["Active", "فعال"],
  fwUFW_inactive: ["Inactive", "غیرفعال"],
  fwUFW_missing: ["Not installed", "نصب نیست"],
  fwIncoming: ["Incoming", "ورودی"],
  fwRouted: ["Forwarded", "عبوری"],
  fwPolicy_allow: ["allow", "مجاز"],
  fwPolicy_deny: ["deny", "مسدود"],
  fwPolicy_reject: ["reject", "رد"],
  fwPolicy_disabled: ["off", "خاموش"],
  fwBackends: ["iptables backends", "بک‌اندهای iptables"],
  fwBackendsHelp: [
    "Both backends can be active at once (UFW often uses legacy, Docker nf_tables). Packets pass both, so a drop in either blocks a forward.",
    "هر دو بک‌اند می‌توانند هم‌زمان فعال باشند (UFW معمولاً legacy و Docker معمولاً nf_tables). بسته‌ها از هر دو عبور می‌کنند، پس رد شدن در هر کدام یک اتصال را مسدود می‌کند.",
  ],
  fwForward: ["FORWARD", "FORWARD"],
  fwGuardOn: ["accept installed", "قانون اجازه نصب است"],
  fwGuardOff: ["accept missing", "قانون اجازه نیست"],
  fwNftables: ["nftables", "nftables"],
  fwNftAvailable: ["Available", "در دسترس"],
  fwNftMissing: ["Not installed", "نصب نیست"],
  fwOtherTables: ["Other tables", "جدول‌های دیگر"],
  fwHost: ["Host", "میزبان"],
  fwUplink: ["Uplink", "رابط اصلی"],
  fwSSH: ["SSH port", "پورت SSH"],
  fwDocker: ["Docker", "Docker"],
  fwFirewalldName: ["firewalld", "firewalld"],
  fwPresent: ["present", "موجود"],

  // Connections
  fwConnections: ["Connections", "اتصال‌ها"],
  fwConnectionsHelp: [
    "Kernel forwards pass the FORWARD chain, where the manager keeps its own accept. Relays (HAProxy, Realm) listen on this server, so UFW must allow their ports.",
    "اتصال‌های کرنل از زنجیره‌ی FORWARD عبور می‌کنند و برنامه قانون اجازه‌ی خودش را آنجا نگه می‌دارد. رله‌ها (HAProxy و Realm) روی همین سرور گوش می‌دهند، پس UFW باید پورتشان را مجاز کند.",
  ],
  fwNoConnections: ["No connections yet", "هنوز اتصالی نیست"],
  fwNoConnectionsBody: [
    "Create a connection first; its ports and access rules appear here.",
    "اول یک اتصال بسازید؛ پورت‌ها و قوانین دسترسی‌اش اینجا نمایش داده می‌شوند.",
  ],
  fwKernelPath: ["Kernel forward · FORWARD", "اتصال کرنل · FORWARD"],
  fwRelayPath: ["Relay on this server · INPUT", "رله روی همین سرور · INPUT"],
  fwPortState_tagged: ["opened here", "باز شده از پنل"],
  fwPortState_open: ["open", "باز"],
  fwPortState_closed: ["closed", "بسته"],
  fwOpenInUFW: ["Open in UFW", "باز در UFW"],
  fwOpenInUFWHelp: [
    "Adds an allow rule tagged with this connection's ID. It follows port changes and is removed with the connection. Ports another rule already opens are left as they are.",
    "یک قانون اجازه با برچسب شناسه‌ی همین اتصال اضافه می‌کند. با تغییر پورت به‌روز می‌شود و با حذف اتصال پاک می‌شود. به پورت‌هایی که قانون دیگری بازشان کرده دست نمی‌زند.",
  ],
  fwAccess: ["Access", "دسترسی"],
  fwAccessEveryone: ["Everyone", "همه"],
  fwAccessAllow: ["Only {n} sources", "فقط {n} مبدأ"],
  fwAccessDeny: ["All but {n} sources", "همه به جز {n} مبدأ"],
  fwLimitPerIP: ["≤{n} per IP", "حداکثر {n} برای هر IP"],
  fwLimitRate: ["≤{n}/s new", "حداکثر {n} اتصال جدید در ثانیه"],
  fwBlocked: ["{n} blocked", "{n} مسدودشده"],
  fwEditAccess: ["Edit access", "ویرایش دسترسی"],
  fwDisabled: ["disabled", "غیرفعال"],

  // Access sheet
  fwAccessTitle: ["Access to {n}", "دسترسی به {n}"],
  fwAccessIntro: [
    "Applies to new connections on {p}. Established ones continue.",
    "روی اتصال‌های جدید به {p} اعمال می‌شود. اتصال‌های برقرار ادامه پیدا می‌کنند.",
  ],
  fwMode: ["Who may connect", "چه کسانی وصل شوند"],
  fwMode_off: ["Everyone", "همه"],
  fwMode_allow: ["Only these", "فقط این‌ها"],
  fwMode_deny: ["Everyone but these", "همه به جز این‌ها"],
  fwSources: ["Addresses or networks", "آدرس‌ها یا شبکه‌ها"],
  fwSourcesHelp: [
    "One per line or comma separated, such as 203.0.113.7 or 198.51.100.0/24. Host bits are cleared.",
    "هر کدام در یک خط یا جداشده با کاما، مثل 203.0.113.7 یا 198.51.100.0/24. بیت‌های میزبان صفر می‌شوند.",
  ],
  fwSourcesInvalid: [
    "Not an address or network: {s}",
    "آدرس یا شبکه‌ی معتبر نیست: {s}",
  ],
  fwSourcesFamily: [
    "Add at least one IPv{f} address; this connection listens on IPv{f}.",
    "حداقل یک آدرس IPv{f} اضافه کنید؛ این اتصال روی IPv{f} گوش می‌دهد.",
  ],
  fwSourcesNeeded: [
    "Add at least one address or network.",
    "حداقل یک آدرس یا شبکه اضافه کنید.",
  ],
  fwPerIP: ["Connections per source", "تعداد اتصال برای هر مبدأ"],
  fwPerIPHelp: [
    "Concurrent connections one address may hold. 0 turns the limit off.",
    "تعداد اتصال هم‌زمانی که یک آدرس می‌تواند داشته باشد. 0 یعنی بدون محدودیت.",
  ],
  fwRate: ["New connections per second", "اتصال جدید در ثانیه"],
  fwRateHelp: [
    "Per source; slows floods and scanners. 0 turns the limit off.",
    "برای هر مبدأ؛ سرعت حمله‌های سیل‌آسا و اسکنرها را کم می‌کند. 0 یعنی بدون محدودیت.",
  ],
  fwLockoutWarn: [
    "If you manage this server through this connection, keep your own address in the list.",
    "اگر سرور را از طریق همین اتصال مدیریت می‌کنید، آدرس خودتان را در فهرست نگه دارید.",
  ],
  fwDone: ["Done", "تأیید"],

  // Protection
  fwProtection: ["Abuse protection", "جلوگیری از abuse"],
  fwProtectionIntro: [
    "Providers such as Hetzner send abuse reports when a server scans private networks or sends spam. These rules stop new uplink traffic from this server, its containers and VPN clients.",
    "دیتاسنترهایی مثل Hetzner وقتی سروری شبکه‌های خصوصی را اسکن کند یا اسپم بفرستد، گزارش abuse می‌فرستند. این قوانین ترافیک جدیدی را که از این سرور، کانتینرها و کاربران VPN به رابط اصلی می‌رود متوقف می‌کنند.",
  ],
  fwPrivate: ["Block private ranges", "مسدود کردن رنج‌های خصوصی"],
  fwPrivateHelp: [
    "New connections to private networks through {u} are dropped. Replies to clients and traffic on other interfaces (GRE, private networks) are unaffected.",
    "اتصال‌های جدید به شبکه‌های خصوصی از طریق {u} مسدود می‌شوند. پاسخ به کاربران و ترافیک رابط‌های دیگر (GRE و شبکه‌های خصوصی) تغییری نمی‌کنند.",
  ],
  fwSMTP: ["Block outgoing mail (port 25)", "مسدود کردن ارسال ایمیل (پورت 25)"],
  fwSMTPHelp: [
    "Stops spam from compromised clients. Mail submission ports 465 and 587 stay open.",
    "جلوی اسپم از کاربران آلوده را می‌گیرد. پورت‌های 465 و 587 برای ارسال ایمیل باز می‌مانند.",
  ],
  fwExceptions: ["Allowed private destinations", "مقصدهای خصوصی مجاز"],
  fwExceptionsHelp: [
    "Private resolvers or services reached through the uplink, such as 10.202.10.10.",
    "DNS یا سرویس‌های خصوصی که از طریق رابط اصلی در دسترس‌اند، مثل 10.202.10.10.",
  ],
  fwAutoExceptions: ["Always allowed (detected)", "همیشه مجاز (تشخیص خودکار)"],
  fwAutoExceptionsHelp: [
    "The default gateway, this server's DNS servers and connection destinations in private ranges.",
    "گیت‌وی پیش‌فرض، DNSهای این سرور و مقصدهای اتصال‌ها که در رنج خصوصی هستند.",
  ],
  fwNoUplink: ["no default route", "بدون مسیر پیش‌فرض"],

  // Save bar and revert
  fwUnsaved: ["Unsaved firewall changes", "تغییرات ذخیره‌نشده‌ی فایروال"],
  fwSafeWindow: ["Undo unless confirmed", "بازگشت خودکار بدون تأیید"],
  fwSafeOff: ["Off", "خاموش"],
  fwSafeSeconds: ["{n} s", "{n} ثانیه"],
  fwSafeMinutes: ["{n} min", "{n} دقیقه"],
  fwSafeHelp: [
    "The server undoes the change by itself unless you confirm it in time, even if this page or your SSH session is cut off.",
    "اگر به‌موقع تأیید نکنید، سرور خودش تغییر را برمی‌گرداند؛ حتی اگر این صفحه یا اتصال SSH شما قطع شود.",
  ],
  fwApply: ["Apply", "اعمال"],
  fwDiscard: ["Discard", "لغو تغییرات"],
  fwPendingTitle: [
    "Confirm the firewall change · {t}",
    "تغییر فایروال را تأیید کنید · {t}",
  ],
  fwPendingBody: [
    "Still connected? Keep it. Otherwise it reverts by itself.",
    "هنوز وصل هستید؟ نگهش دارید. در غیر این صورت خودکار برمی‌گردد.",
  ],
  fwKeep: ["Keep", "نگه داشتن"],
  fwRevertNow: ["Revert now", "برگرداندن"],
} satisfies Messages;
