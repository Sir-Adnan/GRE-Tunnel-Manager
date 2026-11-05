// Server optimization: opt-in sysctl groups, previews, undo and reset.
import type { Messages } from "./types";

export const optimize = {
  optimize: ["Optimization", "بهینه‌سازی"],
  optimizeIntro: [
    "Server-wide kernel settings for tunnel and forwarding servers, in three opt-in groups. Nothing changes until you review and apply a group. Every change can be undone step by step, and Reset returns each setting to its original value and removes the panel's files.",
    "تنظیمات سراسری هسته برای سرورهای تونل و فوروارد، در سه گروه اختیاری. تا گروهی را بررسی و اعمال نکنید هیچ چیزی تغییر نمی‌کند. هر تغییر مرحله‌به‌مرحله قابل برگشت است و «بازنشانی کامل» همهٔ مقدارها را به حالت اول برمی‌گرداند و فایل‌های پنل را پاک می‌کند.",
  ],
  optMemory: ["Memory", "حافظه"],
  optMemoryDetail: [
    "Sizes the connection limit",
    "سقف اتصال‌ها بر اساس آن تعیین می‌شود",
  ],
  optFlows: ["Tracked connections", "اتصال‌های ردیابی‌شده"],
  optFlowsDetail: ["of {max} allowed", "از {max} مجاز"],
  optManaged: ["Managed settings", "تنظیمات مدیریت‌شده"],
  optManagedDetail: ["{n} undo steps", "{n} مرحلهٔ قابل برگشت"],
  optCongestion: ["Congestion control", "کنترل ازدحام"],
  optUndo: ["Undo last step", "برگشت آخرین مرحله"],
  optUndoTitle: ["Undo the last step?", "آخرین مرحله برگردد؟"],
  optUndoBody: [
    "Settings return to the values they had before the last apply or restore. Values someone changed outside the panel since then are left alone.",
    "تنظیمات به مقدارهای پیش از آخرین اعمال یا بازگردانی برمی‌گردند. مقدارهایی که از آن زمان بیرون از پنل تغییر کرده‌اند دست نمی‌خورند.",
  ],
  optReset: ["Reset everything", "بازنشانی کامل"],
  optResetTitle: [
    "Return every setting to its original value?",
    "همهٔ تنظیمات به مقدار اول برگردند؟",
  ],
  optResetBody: [
    "{n} settings return to the values they had before the panel first changed them, and the panel's sysctl and module files are deleted. Undo history is cleared.",
    "{n} تنظیم به مقدار پیش از نخستین تغییر پنل برمی‌گردد و فایل‌های sysctl و ماژول پنل پاک می‌شوند. تاریخچهٔ برگشت هم پاک می‌شود.",
  ],
  optResetButton: ["Reset and remove files", "بازنشانی و حذف فایل‌ها"],
  optNothingManaged: [
    "The panel manages no setting yet.",
    "پنل هنوز هیچ تنظیمی را مدیریت نمی‌کند.",
  ],
  optServerToolsTitle: ["ServerTools is installed", "ServerTools نصب است"],
  optServerToolsBody: [
    "Its settings stay as they are until you apply a group here. The panel's file loads after ServerTools, so for keys both set, the panel's value wins at boot. Rolling ServerTools back later may change them again; check this page afterwards.",
    "تنظیمات آن تا وقتی اینجا گروهی را اعمال نکنید دست نمی‌خورند. فایل پنل بعد از ServerTools بارگذاری می‌شود، پس برای کلیدهای مشترک مقدار پنل هنگام بوت اعمال می‌شود. برگرداندن ServerTools در آینده ممکن است آن‌ها را دوباره تغییر دهد؛ بعد از آن این صفحه را بررسی کنید.",
  ],
  optImportTitle: ["Settings from an earlier version", "تنظیمات نسخهٔ قبلی"],
  optImportBody: [
    "Tuning made with an earlier version was found. It is taken over on your first change here, and Reset returns its keys to their original values as well.",
    "تنظیماتی که با نسخهٔ قبلی انجام شده پیدا شد. با نخستین تغییر در این صفحه تحویل گرفته می‌شود و «بازنشانی کامل» کلیدهای آن را هم به مقدار اول برمی‌گرداند.",
  ],
  optOther: [
    "Also set to {value} by {file}; the panel's value wins at boot.",
    "در {file} هم با مقدار {value} تنظیم شده؛ هنگام بوت مقدار پنل اعمال می‌شود.",
  ],
  optRecommended: ["Recommended", "پیشنهادی"],
  optApplied: ["{n} of {m} applied", "{n} از {m} اعمال شده"],
  optNotApplied: ["Not applied", "اعمال نشده"],
  optDrifted: [
    "{n} changed outside the panel",
    "{n} مورد بیرون از پنل تغییر کرده",
  ],
  optReview: ["Review and apply", "بررسی و اعمال"],
  optRestoreGroup: ["Restore originals", "برگرداندن مقدار اول"],
  optRestoreGroupTitle: [
    "Restore the original values of {group}?",
    "مقدارهای اول «{group}» برگردند؟",
  ],
  optRestoreGroupBody: [
    "Settings of this group return to the values they had before the panel changed them. Other groups stay as they are. You can undo this step.",
    "تنظیمات این گروه به مقدار پیش از تغییر پنل برمی‌گردند و گروه‌های دیگر دست نمی‌خورند. این مرحله قابل برگشت است.",
  ],
  optSetting: ["Setting", "تنظیم"],
  optCurrent: ["Now", "اکنون"],
  optTarget: ["Recommended", "پیشنهادی"],
  optOriginal: ["Original", "مقدار اول"],
  optSame: ["Already recommended", "از قبل همان مقدار پیشنهادی"],
  optMissing: ["Not on this kernel", "در این هسته نیست"],
  optApplyTitle: ["{group}: review changes", "«{group}»: بررسی تغییرات"],
  optApplyBody: [
    "These settings affect the whole server, apply at once and persist after reboot. Each value is compared with the server's own first: limits only grow, timeouts only shrink, and a value that is already better (including the provider's default) stays.",
    "این تنظیمات روی کل سرور اثر دارند، بلافاصله اعمال می‌شوند و بعد از ریبوت هم باقی می‌مانند. هر مقدار اول با مقدار خود سرور مقایسه می‌شود: سقف‌ها فقط بزرگ‌تر و زمان‌ها فقط کوتاه‌تر می‌شوند و مقداری که از قبل بهتر است (از جمله پیش‌فرض دیتاسنتر) حفظ می‌شود.",
  ],
  optApplyButton: ["Apply {n} changes", "اعمال {n} تغییر"],
  optNothing: [
    "This server already meets these values; nothing to change.",
    "این سرور از قبل این مقدارها را دارد؛ چیزی برای تغییر نیست.",
  ],
  optMemoryEstimate: [
    "A completely full connection table would use about {v} of memory; entries cost memory only while connections exist.",
    "جدول اتصال در حالت کاملاً پر حدود {v} حافظه می‌گیرد؛ هر رکورد فقط تا وقتی اتصال وجود دارد حافظه مصرف می‌کند.",
  ],
  optLoadingPlan: ["Reading current values…", "در حال خواندن مقدارهای فعلی…"],
  optFile: ["Written to {file}", "در {file} نوشته می‌شود"],
  optGroup_conntrack: ["Connection tracking", "ردیابی اتصال"],
  optGroupWhy_conntrack: [
    "Fixes ping and jitter that rise over hours and clear after a reboot. Abandoned connections expire in an hour instead of five days, and the table and its index grow with the server's memory.",
    "بالا رفتن پینگ و جیتر بعد از چند ساعت را که با ریبوت درست می‌شود رفع می‌کند. اتصال‌های رهاشده به‌جای پنج روز بعد از یک ساعت پاک می‌شوند و جدول و فهرست آن متناسب با حافظهٔ سرور بزرگ می‌شوند.",
  ],
  optGroupFor_conntrack: [
    "Every server with nftables or iptables forwards.",
    "همهٔ سرورهایی که فوروارد nftables یا iptables دارند.",
  ],
  optGroup_queues: ["Packet queues", "صف بسته‌ها"],
  optGroupWhy_queues: [
    "Lets the network card hand more packets to the kernel per pass and keeps short bursts from being dropped.",
    "به کارت شبکه اجازه می‌دهد در هر نوبت بسته‌های بیشتری به هسته تحویل دهد و از دور ریختن بسته‌ها در ترافیک لحظه‌ای جلوگیری می‌کند.",
  ],
  optGroupFor_queues: [
    "Busy servers with many users or high packet rates.",
    "سرورهای شلوغ با کاربران زیاد یا نرخ بستهٔ بالا.",
  ],
  optGroup_relay: ["Relay TCP", "TCP رله‌ها"],
  optGroupWhy_relay: [
    "For HAProxy, Realm and FRP connections this server makes itself: BBR and pacing for lossy international links, larger buffers for long distances, MTU probing for tunnels, and keepalives that hold idle connections open within the connection-tracking timeout.",
    "برای اتصال‌هایی که خود این سرور در HAProxy، Realm و FRP برقرار می‌کند: BBR و ارسال یکنواخت برای مسیرهای بین‌المللی پراتلاف، بافر بزرگ‌تر برای فاصلهٔ زیاد، کاوش MTU برای تونل‌ها و keepalive که اتصال‌های بی‌کار را در محدودهٔ زمان ردیابی اتصال باز نگه می‌دارد.",
  ],
  optGroupFor_relay: [
    "Servers that run HAProxy, Realm, FRP or rathole. Kernel forwards do not use these.",
    "سرورهایی که HAProxy، Realm، FRP یا rathole دارند. فورواردهای هسته از این‌ها استفاده نمی‌کنند.",
  ],
  "optWhy_flow-limit": [
    "Room for every user's connections; sized to about 8 % of memory.",
    "جا برای اتصال‌های همهٔ کاربران؛ حدود 8 درصد حافظه.",
  ],
  "optWhy_flow-buckets": [
    "Index size; half the limit keeps lookups short when the table is full.",
    "اندازهٔ فهرست؛ نصف سقف، جست‌وجو را در جدول پر هم کوتاه نگه می‌دارد.",
  ],
  "optWhy_idle-tcp": [
    "Forget idle connections after 1 hour instead of 5 days.",
    "فراموش کردن اتصال‌های بی‌کار بعد از 1 ساعت به‌جای 5 روز.",
  ],
  "optWhy_closing-tcp": [
    "Free closing connections in 30 seconds.",
    "آزاد کردن اتصال‌های در حال بسته شدن در 30 ثانیه.",
  ],
  optWhy_udp: [
    "Keep one-way UDP mappings a little longer.",
    "نگه داشتن نگاشت‌های UDP یک‌طرفه کمی طولانی‌تر.",
  ],
  "optWhy_udp-stream": [
    "Keep WireGuard and QUIC sessions mapped between packets.",
    "نگه داشتن نشست‌های WireGuard و QUIC بین بسته‌ها.",
  ],
  optWhy_backlog: [
    "Queue more received packets per core before dropping.",
    "صف کردن بستهٔ بیشتر برای هر هسته پیش از دور ریختن.",
  ],
  optWhy_budget: [
    "Process more packets per pass.",
    "پردازش بستهٔ بیشتر در هر نوبت.",
  ],
  "optWhy_accept-queue": [
    "Longer accept queue for relay listeners.",
    "صف پذیرش بلندتر برای شنونده‌های رله.",
  ],
  "optWhy_syn-queue": [
    "Absorb bursts of new connections.",
    "تحمل هجوم ناگهانی اتصال‌های جدید.",
  ],
  optWhy_pacing: [
    "Fair-queue pacing that BBR works best with (new interfaces or after reboot).",
    "صف منصفانه که BBR با آن بهترین کارایی را دارد (رابط‌های جدید یا بعد از ریبوت).",
  ],
  optWhy_bbr: [
    "Keeps throughput high on links with loss.",
    "حفظ سرعت در مسیرهای دارای اتلاف بسته.",
  ],
  optWhy_buffers: [
    "Larger windows for distant servers.",
    "پنجرهٔ بزرگ‌تر برای سرورهای دور.",
  ],
  "optWhy_mtu-probing": [
    "Recover when a tunnel silently drops large packets.",
    "بازیابی وقتی تونل بسته‌های بزرگ را بی‌صدا دور می‌ریزد.",
  ],
  "optWhy_idle-restart": [
    "Do not slow down again after a pause.",
    "کند نشدن دوباره بعد از مکث.",
  ],
  optWhy_keepalive: [
    "Probe idle relay connections every 10 minutes, well inside the 1-hour tracking timeout.",
    "بررسی اتصال‌های بی‌کار رله هر 10 دقیقه، پیش از پایان زمان 1 ساعتهٔ ردیابی.",
  ],
  "optWhy_fin-timeout": [
    "Release half-closed relay sockets sooner.",
    "آزاد کردن زودتر سوکت‌های نیمه‌بستهٔ رله.",
  ],
  "optWhy_tw-reuse": [
    "Reuse ports of closed outgoing connections safely.",
    "استفادهٔ امن دوباره از پورت اتصال‌های خروجی بسته‌شده.",
  ],
  optKeyFlowLimit: ["Connection limit", "سقف اتصال‌ها"],
  optKeyBuckets: ["Index buckets", "خانه‌های فهرست"],
  optKeyIdleTcp: ["Idle TCP kept", "نگهداری TCP بی‌کار"],
  optKeyTimeWait: ["TCP TIME-WAIT", "TCP در TIME-WAIT"],
  optKeyFinWait: ["TCP FIN-WAIT", "TCP در FIN-WAIT"],
  optKeyCloseWait: ["TCP CLOSE-WAIT", "TCP در CLOSE-WAIT"],
  optKeyUdp: ["UDP one-way", "UDP یک‌طرفه"],
  optKeyUdpStream: ["UDP streams", "جریان‌های UDP"],
  optKeyBacklog: ["Receive backlog", "صف دریافت"],
  optKeyBudget: ["Packets per pass", "بسته در هر نوبت"],
  optKeyBudgetTime: ["Time per pass (µs)", "زمان هر نوبت (µs)"],
  optKeyAcceptQueue: ["Accept queue", "صف پذیرش"],
  optKeySynQueue: ["SYN queue", "صف SYN"],
  optKeyQdisc: ["Default queue discipline", "نظم صف پیش‌فرض"],
  optKeyCongestion: ["Congestion control", "کنترل ازدحام"],
  optKeyRmemMax: ["Max receive buffer", "حداکثر بافر دریافت"],
  optKeyWmemMax: ["Max send buffer", "حداکثر بافر ارسال"],
  optKeyTcpRmem: ["TCP receive window", "پنجرهٔ دریافت TCP"],
  optKeyTcpWmem: ["TCP send window", "پنجرهٔ ارسال TCP"],
  optKeyMtuProbing: ["MTU probing", "کاوش MTU"],
  optKeySlowStart: ["Slow start after idle", "شروع آهسته بعد از مکث"],
  optKeyKeepalive: ["Keepalive after", "keepalive پس از"],
  optKeyKeepaliveInterval: ["Keepalive interval", "فاصلهٔ keepalive"],
  optKeyKeepaliveProbes: ["Keepalive probes", "تعداد keepalive"],
  optKeyFinTimeout: ["FIN timeout", "زمان FIN"],
  optKeyTwReuse: ["Reuse TIME-WAIT ports", "استفادهٔ دوباره از پورت TIME-WAIT"],
  optMore: ["More actions", "کارهای بیشتر"],
  optHeroTitle: [
    "{n} improvements available for this server",
    "{n} بهبود برای این سرور آماده است",
  ],
  optHeroNone: ["This server is up to date", "این سرور به‌روز است"],
  optHeroDetail: [
    "{a} of {g} groups applied. Recommendations never make a value your server already has worse.",
    "{a} از {g} گروه اعمال شده. پیشنهادها هیچ مقداری را که سرور شما از قبل دارد بدتر نمی‌کنند.",
  ],
  optReviewRecommended: ["Review recommendations", "بررسی پیشنهادها"],
  optRecommendedTitle: [
    "Recommendations for this server",
    "پیشنهادهای این سرور",
  ],
  optFitBadge: ["Fits this server", "مناسب این سرور"],
  optImprovements: ["{n} improvements", "{n} بهبود"],
  optPartly: ["Applied · {n} more", "اعمال شده · {n} مورد دیگر"],
  optAllApplied: ["Applied", "اعمال شده"],
  optUpToDate: ["Already optimal", "از قبل بهینه"],
  optKept: ["Server value is better; kept", "مقدار سرور بهتر است؛ حفظ می‌شود"],
  optManagedKey: ["Managed", "مدیریت‌شده"],
  optOriginalValue: ["Original {v}", "مقدار اول {v}"],
  optPlanChanges: ["{n} changes", "{n} تغییر"],
  optPlanKept: [
    "{n} server values are already better and stay as they are.",
    "{n} مقدار سرور از قبل بهتر است و دست نمی‌خورد.",
  ],
  optUnchanged: ["No change needed ({n})", "بدون نیاز به تغییر ({n})"],
  optSafetyTitle: ["How changes stay safe", "تغییرات چطور امن می‌مانند"],
  optSafety1: [
    "Never worse: each value is compared with what the server has now, including the provider's defaults, and kept when it is already as good.",
    "هرگز بدتر نمی‌شود: هر مقدار با مقدار فعلی سرور، از جمله پیش‌فرض دیتاسنتر، مقایسه می‌شود و اگر به همان خوبی باشد حفظ می‌شود.",
  ],
  optSafety2: [
    "Every apply is one undo step; a group can return to its original values on its own.",
    "هر اعمال یک مرحلهٔ قابل برگشت است و هر گروه جداگانه به مقدارهای اول برمی‌گردد.",
  ],
  optSafety3: [
    "Reset everything restores every original value and deletes the panel's files.",
    "بازنشانی کامل همهٔ مقدارهای اول را برمی‌گرداند و فایل‌های پنل را پاک می‌کند.",
  ],
  optHistoryTitle: ["History", "تاریخچه"],
  optHistoryBody: [
    "{n} settings managed · {s} undo steps",
    "{n} تنظیم مدیریت‌شده · {s} مرحلهٔ قابل برگشت",
  ],
  optFilesTitle: ["Files", "فایل‌ها"],
  optGroup_routing: ["Tunnels & routing", "تونل و مسیریابی"],
  optGroupWhy_routing: [
    "Strict reverse-path filtering drops replies that come back on a different interface, which breaks GRE and additional IPs with their own gateway; loose mode still drops spoofed sources the host cannot route at all. A forwarder should also neither send nor accept ICMP redirects.",
    "فیلتر سخت‌گیرانهٔ مسیر برگشت، پاسخ‌هایی را که از رابط دیگری برمی‌گردند دور می‌ریزد و GRE و IPهای اضافه با گیت‌وی جدا را خراب می‌کند؛ حالت آزاد همچنان مبداهای جعلی‌ای را که سرور اصلاً مسیری به آن‌ها ندارد دور می‌ریزد. سرور فوروارد همچنین نباید ICMP redirect بفرستد یا بپذیرد.",
  ],
  optGroupFor_routing: [
    "Servers with GRE or more than one IP address.",
    "سرورهای دارای GRE یا بیش از یک نشانی IP.",
  ],
  optWhy_notsent: [
    "Keep less unsent data per socket, which lowers relay latency under BBR.",
    "نگه داشتن دادهٔ ارسال‌نشدهٔ کمتر در هر سوکت؛ تأخیر رله را با BBR کم می‌کند.",
  ],
  "optWhy_rp-filter": [
    "Strict becomes loose; an existing off or loose setting stays.",
    "حالت سخت‌گیرانه آزاد می‌شود؛ حالت خاموش یا آزاد موجود حفظ می‌شود.",
  ],
  optWhy_redirects: [
    "Do not tell clients to bypass this server.",
    "به کلاینت‌ها نگفتن که این سرور را دور بزنند.",
  ],
  "optWhy_accept-redirects": [
    "Ignore route changes sent by other hosts.",
    "نادیده گرفتن تغییر مسیری که میزبان‌های دیگر می‌فرستند.",
  ],
  optKeyNotsent: ["Unsent data per socket", "دادهٔ ارسال‌نشده در هر سوکت"],
  optKeyRpFilterAll: ["Reverse-path filter (all)", "فیلتر مسیر برگشت (همه)"],
  optKeyRpFilterDefault: [
    "Reverse-path filter (new interfaces)",
    "فیلتر مسیر برگشت (رابط‌های جدید)",
  ],
  optKeySendRedirectsAll: ["Send redirects (all)", "ارسال redirect (همه)"],
  optKeySendRedirectsDefault: [
    "Send redirects (new interfaces)",
    "ارسال redirect (رابط‌های جدید)",
  ],
  optKeyAcceptRedirectsAll: ["Accept redirects (all)", "پذیرش redirect (همه)"],
  optKeyAcceptRedirectsDefault: [
    "Accept redirects (new interfaces)",
    "پذیرش redirect (رابط‌های جدید)",
  ],
} satisfies Messages;
