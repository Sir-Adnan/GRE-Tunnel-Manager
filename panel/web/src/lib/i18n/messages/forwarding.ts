// Connection editor: steps, port ranges and mapping, domain destinations,
// health and protection, the route map and drag-and-drop ordering.
import type { Messages } from "./types";

export const forwarding = {
  safeRetryFailed: [
    "Automatic revert needs attention. Check the error and retry, or keep the change explicitly.",
    "بازگردانی خودکار نیاز به بررسی دارد. خطا را بررسی و دوباره تلاش کنید، یا تغییر را صریحاً نگه دارید.",
  ],
  savedDNSPolicyFailed: [
    "The connection was saved, but some DNS settings could not be applied. Reopen the connection to review them; do not create it again.",
    "اتصال ذخیره شد، اما بعضی تنظیمات DNS اعمال نشد. برای بررسی، همان اتصال را دوباره باز کنید و اتصال تکراری نسازید.",
  ],
  stepEntrance: ["Entrance", "ورودی"],
  stepDestinations: ["Destinations", "مقصدها"],
  stepProtection: ["Protection & review", "محافظت و بازبینی"],
  next: ["Next", "بعدی"],
  duplicateConnection: ["Duplicate connection", "تکثیر اتصال"],
  duplicate: ["Duplicate", "تکثیر"],
  duplicateHelp: [
    "Same settings on a free port",
    "همان تنظیمات روی یک پورت آزاد",
  ],
  advancedOptions: [
    "Advanced: listen address, limits and routing",
    "پیشرفته: آدرس شنود، محدودیت‌ها و مسیریابی",
  ],

  portsHelpKernel: [
    "Ports and ranges separated by commas. A range such as 2000-2999 (up to 4096 ports) is one kernel rule, so large ranges stay fast.",
    "پورت‌ها و بازه‌ها را با کاما جدا کنید. بازه‌ای مثل 2000-2999 (تا 4096 پورت) فقط یک قانون کرنل است و بازه‌های بزرگ هم سریع می‌مانند.",
  ],
  portsSummary: ["{n} ports · {r} connections", "{n} پورت · {r} اتصال"],
  portsSummaryKernel: [
    "{n} ports · {r} kernel rules",
    "{n} پورت · {r} قانون کرنل",
  ],
  portsError_empty: [
    "Enter a port, a list or a range.",
    "یک پورت، فهرست یا بازه وارد کنید.",
  ],
  portsError_invalid: [
    "Use ports 1–65535 and ascending ranges such as 2000-2999 (at most 4096 ports).",
    "از پورت‌های 1 تا 65535 و بازه‌های صعودی مثل 2000-2999 (حداکثر 4096 پورت) استفاده کنید.",
  ],
  portsError_overlap: ["These ranges overlap.", "این بازه‌ها هم‌پوشانی دارند."],
  portsError_tooMany: [
    "Use at most 32 ports or ranges at once.",
    "در هر بار حداکثر 32 پورت یا بازه.",
  ],
  portsError_relayRange: [
    "This engine opens one listener per port: use ranges of up to 32 ports, or nftables/iptables for larger ones.",
    "این موتور برای هر پورت یک شنونده باز می‌کند: بازه تا 32 پورت، یا برای بازه‌های بزرگ‌تر nftables/iptables.",
  ],
  portsError_mapCount: [
    "Enter as many remote ports or ranges as local ones, in the same order.",
    "به همان تعداد و ترتیب پورت‌ها و بازه‌های محلی، پورت یا بازهٔ مقصد وارد کنید.",
  ],
  portsError_mapSize: [
    "Each remote range must be the same size as its local range (or one port).",
    "هر بازهٔ مقصد باید هم‌اندازهٔ بازهٔ محلی‌اش باشد (یا یک پورت).",
  ],
  portMapping: ["Remote ports", "پورت‌های مقصد"],
  portMappingHelp: [
    "How the incoming ports reach the destination. Same port keeps each number; one port sends all of them to the destination port; mapped pairs them in order, such as 2000-2999 → 3000-3999.",
    "پورت‌های ورودی چطور به مقصد برسند. «همان پورت» هر شماره را حفظ می‌کند؛ «یک پورت» همه را به پورت مقصد می‌فرستد؛ «نگاشت» آن‌ها را به ترتیب جفت می‌کند، مثل 2000-2999 → 3000-3999.",
  ],
  portModeSame: ["Same port", "همان پورت"],
  portModeSameHelp: [
    "2000 → 2000, 2001 → 2001 …",
    "2000 → 2000، 2001 → 2001 …",
  ],
  portModeSameShort: ["same as incoming", "همان پورت ورودی"],
  portModeOne: ["One port", "یک پورت"],
  portModeOneHelp: ["All to the destination port", "همه به پورت مقصد"],
  portModeOneShort: ["destination port", "پورت مقصد"],
  portModeMap: ["Mapped", "نگاشت"],
  portModeMapHelp: ["2000-2999 → 3000-3999", "2000-2999 → 3000-3999"],
  portModeMapNft: [
    "Mapping to other port numbers needs nftables; iptables keeps the same ports or sends all to one.",
    "نگاشت به شماره‌های دیگر به nftables نیاز دارد؛ iptables همان پورت را نگه می‌دارد یا همه را به یک پورت می‌فرستد.",
  ],
  remotePorts: ["Remote ports (same order)", "پورت‌های مقصد (به همان ترتیب)"],
  remotePortsHelp: [
    "One entry per local port or range, each the same size. A single port receives the whole range.",
    "برای هر پورت یا بازهٔ محلی یک مورد، با همان اندازه. یک پورت تکی کل بازه را دریافت می‌کند.",
  ],
  portMappingPreview: ["Mapping preview", "پیش‌نمایش نگاشت"],

  remoteAddress: ["Address or domain", "آدرس یا دامنه"],
  targetPriority: [
    "Order: the first destination is the primary one",
    "ترتیب: مقصد اول، مقصد اصلی است",
  ],
  targetOrderHelp: [
    "Tap a destination to edit it. Drag the handle or use ⋯ to reorder; with primary + backup the first one is the primary and the order is the failover priority.",
    "برای ویرایش، روی مقصد بزنید. برای تغییر ترتیب، دستگیره را بکشید یا از ⋯ استفاده کنید؛ در حالت اصلی و پشتیبان، مقصد اول اصلی است و ترتیب، اولویت جایگزینی است.",
  ],
  dnsChecking: ["Checking the domain…", "در حال بررسی دامنه…"],
  dnsNoAddress: [
    "This domain has no usable address right now.",
    "این دامنه الان آدرس قابل‌استفاده‌ای ندارد.",
  ],
  dnsNoAddressBlock: [
    "A domain destination does not resolve. Fix it or wait until it does.",
    "یکی از دامنه‌های مقصد resolve نمی‌شود. آن را اصلاح کنید یا صبر کنید تا در دسترس شود.",
  ],
  dnsResolves: ["Resolves to {n}:", "به {n} آدرس می‌رسد:"],
  dnsRefresh: ["Check the domain", "بررسی دوبارهٔ دامنه"],
  dnsRefreshHelp: [
    "The server looks the domain up again on this schedule and updates the rules only when an address changes. If a lookup fails, the last addresses keep working.",
    "سرور در این فاصله دامنه را دوباره بررسی می‌کند و فقط وقتی آدرس عوض شود قوانین را به‌روز می‌کند. اگر بررسی ناموفق باشد، آخرین آدرس‌ها کار می‌کنند.",
  ],
  dnsEvery: ["Every {n} min", "هر {n} دقیقه"],
  dnsMode: ["With several addresses", "با چند آدرس"],
  dnsModeHelp: [
    "All: every address receives traffic (balancing and failover apply). First: one stable address.",
    "همه: هر آدرس ترافیک می‌گیرد (توزیع بار و جایگزینی خودکار اعمال می‌شود). اولی: یک آدرس ثابت.",
  ],
  dnsModeAll: ["All as destinations", "همه به‌عنوان مقصد"],
  dnsModeFirst: ["Only the first address", "فقط آدرس اول"],

  protectTitle: ["Health and protection", "سلامت و محافظت"],
  protectHelp: [
    "Checks run from this server in the background; nothing changes in the data path.",
    "بررسی‌ها از همین سرور در پس‌زمینه انجام می‌شوند؛ مسیر داده تغییری نمی‌کند.",
  ],
  protectAdvanced: ["Health settings", "تنظیمات سلامت"],
  protectHealthOff: [
    "Health checks are off on this server",
    "بررسی سلامت روی این سرور خاموش است",
  ],
  protectHealthOffHelp: [
    "Turn them on to watch this connection: a check every {s} s, down after {n} failures.",
    "برای پایش این اتصال روشنش کنید: هر {s} ثانیه یک بررسی، و بعد از {n} خطا قطع اعلام می‌شود.",
  ],
  protectTurnOn: ["Turn on health checks", "روشن کردن بررسی سلامت"],
  protectMonitor: ["Monitor this connection", "پایش این اتصال"],
  protectMonitorHelp: [
    "Every {s} s; down after {n} failures in a row",
    "هر {s} ثانیه؛ بعد از {n} خطای پشت‌سرهم قطع اعلام می‌شود",
  ],
  protectMonitorHelpShort: [
    "Uptime, latency and outages on the Health page",
    "زمان دسترسی، تأخیر و قطعی‌ها در صفحهٔ سلامت",
  ],
  protectFailover: ["Automatic failover", "جایگزینی خودکار"],
  protectFailoverHelp: [
    "A dead destination gets no new connections until it recovers",
    "مقصد از کار افتاده تا وقتی برگردد اتصال جدید نمی‌گیرد",
  ],
  protectFailoverNeeds: [
    "Needs two or more destinations",
    "به دو مقصد یا بیشتر نیاز دارد",
  ],
  protectFailoverRelay: [
    "HAProxy fails over with its own checks (Primary / backup); Realm does not fail over",
    "HAProxy با بررسی‌های خودش جایگزین می‌کند (اصلی / پشتیبان)؛ Realm جایگزینی ندارد",
  ],
  protectNotify: ["Notify me", "به من خبر بده"],
  protectNotifyHelp: [
    "Outages go to your webhook and Telegram (always in the panel)",
    "قطعی‌ها به وب‌هوک و تلگرام شما می‌رود (همیشه در پنل)",
  ],
  safeApply: ["Safe apply", "اعمال امن"],
  safeApplyHelp: [
    "Useful when you change the connection you are using right now (for example SSH through this tunnel): if you do not confirm in time, the previous configuration comes back by itself.",
    "وقتی اتصالی را تغییر می‌دهید که همین الان از آن استفاده می‌کنید (مثلاً SSH از همین تونل) مفید است: اگر به‌موقع تأیید نکنید، پیکربندی قبلی خودکار برمی‌گردد.",
  ],
  safeApplyOff: ["Off", "خاموش"],
  safeApplyMinutes: [
    "Revert in {n} min unless confirmed",
    "برگشت بعد از {n} دقیقه، مگر تأیید شود",
  ],

  routeMap: ["Route map", "نقشهٔ مسیر"],
  routeClients: ["Clients reach", "کاربران وصل می‌شوند به"],
  routePorts: ["{n} ports · {r} rules", "{n} پورت · {r} قانون"],
  routeMapped: ["mapped", "نگاشت‌شده"],
  routeResolving: ["resolving…", "در حال resolve…"],
  routeMonitored: ["Monitored", "پایش می‌شود"],
  routeNotMonitored: ["Not monitored", "پایش نمی‌شود"],

  dragHandle: ["Move", "جابه‌جایی"],
  dragInstructions: [
    "Drag the handle with the mouse or a finger, or press and hold a row on a touch screen. With the keyboard, focus the handle and use the arrow keys to move one place.",
    "دستگیره را با ماوس یا انگشت بکشید، یا در صفحه‌ی لمسی انگشت را روی ردیف نگه دارید. با صفحه‌کلید روی دستگیره فوکوس کنید و با کلیدهای جهت یک جایگاه جابه‌جا کنید.",
  ],
  dragPicked: ["Picked up item {n}.", "مورد {n} برداشته شد."],
  dragOver: ["Over position {n}.", "روی جایگاه {n}."],
  dragDropped: ["Dropped at position {n}.", "در جایگاه {n} رها شد."],
  dragCancelled: ["Move cancelled.", "جابه‌جایی لغو شد."],
  overviewBlockKpi: ["Server figures", "آمار سرور"],
  overviewBlockStatus: [
    "Live status and attention",
    "وضعیت زنده و موارد نیازمند توجه",
  ],
  id: ["Tunnel ID", "شناسهٔ تونل"],
  remote: ["Other server's IP", "آی‌پی سرور دیگر"],
  orderSaveFailed: [
    "The new order could not be saved: {e}",
    "ترتیب جدید ذخیره نشد: {e}",
  ],
  // Connection form sections, method cards and field errors.
  nextStep: ["Next: {step}", "بعدی: {step}"],
  stepOf: ["Step {n} of {total}", "مرحله‌ی {n} از {total}"],
  sectionMethod: ["Method", "روش انتقال"],
  sectionMethodHelp: [
    "What carries the traffic on this server.",
    "چه چیزی ترافیک را روی این سرور جابه‌جا می‌کند.",
  ],
  engineBlurb_nftables: [
    "In the kernel; fastest path and large port ranges.",
    "در کرنل؛ سریع‌ترین مسیر و بازه‌های بزرگ پورت.",
  ],
  engineBlurb_iptables: [
    "In the kernel; for servers that use iptables.",
    "در کرنل؛ برای سرورهایی که iptables دارند.",
  ],
  engineBlurb_haproxy: [
    "TCP proxy with health checks and graceful reloads.",
    "پراکسی TCP با بررسی سلامت و بارگذاری بدون قطعی.",
  ],
  engineBlurb_realm: [
    "Light relay for TCP and UDP.",
    "رله‌ی سبک برای TCP و UDP.",
  ],
  sectionEntranceHelp: [
    "The ports clients connect to on this server.",
    "کاربران به کدام پورت‌های این سرور وصل می‌شوند.",
  ],
  protocolFixed: [
    "{engine} carries {p} only.",
    "{engine} فقط {p} را منتقل می‌کند.",
  ],
  sectionIdentity: ["Name and start", "نام و اجرا"],
  sectionIdentityHelp: [
    "All optional; the defaults suit most connections.",
    "همه اختیاری‌اند؛ پیش‌فرض‌ها برای بیشتر اتصال‌ها مناسب‌اند.",
  ],
  sectionTargetsHelp: [
    "The servers this connection sends traffic to.",
    "سرورهایی که این اتصال ترافیک را به آن‌ها می‌فرستد.",
  ],
  sectionSpread: ["Traffic spread", "تقسیم ترافیک"],
  sectionSpreadHelp: [
    "How new connections are shared and how often domains are looked up.",
    "اتصال‌های جدید چطور تقسیم شوند و دامنه‌ها هر چند وقت بررسی شوند.",
  ],
  sectionReview: ["Review", "بازبینی"],
  sectionReviewHelp: [
    "One look before saving.",
    "پیش از ذخیره یک بار نگاه کنید.",
  ],
  tmplPick: [
    "Pick one to fill the method, ports and destination shape; every field stays editable.",
    "یکی را انتخاب کنید تا روش، پورت‌ها و شکل مقصد پر شوند؛ همه‌ی فیلدها قابل ویرایش می‌مانند.",
  ],
  routeNoPorts: ["No port yet", "هنوز پورتی وارد نشده"],
  destinationsCount: ["Destinations: {n}", "{n} مقصد"],
  fieldRequired: ["Fill in this field.", "این فیلد را پر کنید."],
  fieldInvalid: ["This value is not valid.", "این مقدار معتبر نیست."],
  fieldRange: [
    "Enter a number from {min} to {max}.",
    "عددی از {min} تا {max} وارد کنید.",
  ],
  fieldTooLong: [
    "Use at most {n} characters.",
    "حداکثر {n} نویسه وارد کنید.",
  ],
  fieldsToFix: [
    "{n} fields need a fix:",
    "{n} فیلد نیاز به اصلاح دارد:",
  ],
} satisfies Messages;
