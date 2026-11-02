// Nodes (Agents), pairing and node traffic.
import { panelVersion } from "../../version";
import type { Messages } from "./types";

export const nodes = {
  nodeCapabilitiesHelp: [
    "Agents initially report inventory. To create paired GRE/FRP, add --operations to the Agent installer. Traffic reports require --traffic and local collection setup.",
    "ایجنت در ابتدا فقط اطلاعات سرور را می‌فرستد. برای ساخت GRE و FRP بین دو سرور، هنگام نصب گزینهٔ --operations را اضافه کنید. گزارش مصرف به --traffic و فعال‌کردن ثبت مصرف روی نود نیاز دارد.",
  ],
  nodeStepAgentHelp: [
    "Run this on the other server. Paste the one-time code when asked; it connects automatically. No inbound Agent port is needed.",
    "این دستور را روی سرور دیگر اجرا کنید و وقتی خواست، کد اتصال را وارد کنید. ایجنت خودکار وصل می‌شود و به پورت ورودی نیاز ندارد.",
  ],
  nodeStepInviteHelp: [
    "Choose Add server, name it, and copy its one-time code.",
    "روی «افزودن سرور» بزنید، نامش را بنویسید و کد یک‌بارمصرف را کپی کنید.",
  ],
  nodeStepAgent: ["3. Install the Agent", "مرحلهٔ 3: نصب ایجنت"],
  nodeStepInvite: ["2. Create an enrollment code", "مرحلهٔ 2: ساخت کد اتصال"],
  nodeStepController: [
    "1. Prepare the panel server",
    "مرحلهٔ 1: آماده‌کردن سرور پنل",
  ],
  controllerHTTPNote: [
    "HTTP is for your browser. Agents use a separate TLS connection on port 9443 with their own pinned certificates. No browser HTTPS certificate is needed.",
    "ارتباط مرورگر می‌تواند HTTP باشد. ایجنت‌ها با گواهی مخصوص خودشان از پورت جداگانهٔ TLS روی 9443 وصل می‌شوند؛ گواهی HTTPS مرورگر لازم نیست.",
  ],
  controllerAddress: ["Panel server IP or domain", "آی‌پی یا دامنهٔ سرور پنل"],
  controllerSetupStep: [
    "Run this on the panel server, then refresh this page. Open TCP port 9443 in your server firewall.",
    "این دستور را روی سرور پنل اجرا کنید، پورت TCP 9443 را در فایروال سرور باز کنید و سپس این صفحه را تازه کنید.",
  ],
  controllerRequiredHelp: [
    "First enable the Agent listener on this panel server. Your browser can continue using HTTP.",
    "ابتدا سرویس اتصال ایجنت‌ها را روی همین سرور راه بیندازید. پنل می‌تواند همچنان با HTTP باز شود.",
  ],
  nodeTraffic: ["Traffic", "مصرف ترافیک"],
  nodeTrafficObserved: ["Report received", "زمان دریافت گزارش"],
  nodeTrafficNoSamples: ["No samples yet", "هنوز نمونه‌ای ثبت نشده"],
  nodeTrafficUnknown: [
    "Resource absent from inventory",
    "اتصال در موجودی فعلی نیست",
  ],
  nodeTrafficCurrent: ["Current cycle", "دورهٔ فعلی"],
  readOnly: ["Read only", "فقط مشاهده"],
  nodeTrafficHelp: [
    "Optional snapshots from this server, refreshed every 60 seconds while this tab is open. Refresh reads the latest report; it does not trigger a new sample. Received/sent follow the server interface or entrance direction. Overlapping GRE and forwarding bytes are never summed. Configure collection locally; remote reset, quotas and history are not available here.",
    "گزارش اختیاری همین سرور است و تا وقتی این تب باز باشد، هر 60 ثانیه به‌روز می‌شود. دکمهٔ به‌روزرسانی آخرین گزارش دریافتی را می‌خواند و نمونهٔ جدید نمی‌گیرد. جهت دریافت و ارسال نسبت به رابط یا ورودی سرور است. مصرف GRE و فوروارد ممکن است هم‌پوشانی داشته باشد و جمع نمی‌شود. تنظیم ثبت مصرف روی خود نود انجام می‌شود؛ ریست، سقف و تاریخچهٔ راه دور هنوز در این بخش نیست.",
  ],
  nodeTrafficWaiting: ["No traffic report yet", "هنوز گزارش مصرفی نرسیده"],
  nodeTrafficSetup: [
    "Install or update this Agent with --traffic, then enable collection locally. Existing identities are preserved. Older Agents can keep reporting inventory without traffic.",
    "برای این نود، نصب‌کننده را با گزینهٔ --traffic اجرا کنید و سپس ثبت مصرف را روی خود نود روشن کنید. هویت فعلی حفظ می‌شود. ایجنت قدیمی هم می‌تواند بدون گزارش مصرف، موجودی را ارسال کند.",
  ],
  nodeTrafficStale: [
    "These are the last reported values. The report is old or collection encountered a problem; check the Agent and its last sample time.",
    "این اعداد آخرین مقادیر گزارش‌شده‌اند. گزارش قدیمی است یا ثبت مصرف با مشکل روبه‌رو شده؛ وضعیت ایجنت و زمان آخرین نمونه را بررسی کنید.",
  ],
  nodeTrafficEmpty: [
    "Collection may be paused, or no supported resource has been sampled yet. Enable it on the Node with sudo gtm-panel nodes traffic --enable.",
    "ممکن است ثبت مصرف خاموش باشد یا هنوز نمونه‌ای از اتصال‌های قابل شمارش ثبت نشده باشد. برای روشن‌کردن آن، روی خود نود دستور sudo gtm-panel nodes traffic --enable را اجرا کنید.",
  ],
  nodeTrafficSample: ["Last sample", "آخرین نمونه"],
  nodeTrafficCycle: ["Cycle started", "شروع دوره"],

  connectionTopology: ["Entrance to destination", "مسیر ورودی به مقصد"],
  swapNodes: ["Swap entrance and destination", "جابه‌جایی ورودی و خروجی"],
  server: ["Server", "سرور"],
  tunnelId: ["GRE ID", "شناسهٔ GRE"],
  pairedConnections: ["Connect two servers", "اتصال دو سرور"],
  pairedConnectionsHelp: [
    "Create GRE or FRP on both servers from a single guided setup.",
    "تونل GRE یا FRP را با یک راهنمای ساده روی هر دو سرور بسازید.",
  ],
  noPairJobs: [
    "Your coordinated connections will appear here.",
    "اتصال‌های ساخته‌شده بین دو سرور اینجا نمایش داده می‌شوند.",
  ],
  pairCreate: ["New connection", "اتصال جدید"],
  pairEntrance: ["Entrance server", "سرور ورودی"],
  pairDestination: ["Destination server", "سرور مقصد"],
  pairEntranceIP: ["Entrance IP", "آی‌پی ورودی"],
  pairDestinationIP: ["Destination IP", "آی‌پی مقصد"],
  pairAddressHelp: [
    "Use a concrete IP assigned to the server and reachable from its peer. Automatic NAT mapping is not supported.",
    "آی‌پی باید روی سرور تنظیم شده و از سمت مقابل در دسترس باشد. نگاشت خودکار NAT پشتیبانی نمی‌شود.",
  ],
  pairNameHelp: [
    "Optional display name. Leave blank for an automatic name.",
    "نام نمایشی اختیاری است؛ خالی بگذارید تا خودکار انتخاب شود.",
  ],
  pairPublicPort: ["Public port", "پورت ورودی کاربران"],
  pairControlPort: ["Tunnel control port", "پورت ارتباط دو سرور"],
  pairServiceIP: ["Service IP on destination", "آی‌پی سرویس روی مقصد"],
  pairServicePort: ["Service port on destination", "پورت سرویس روی مقصد"],
  pairReview: ["Review connection", "بررسی اتصال"],
  pairReviewHelp: [
    "Review both servers before starting. Existing resources are never overwritten.",
    "پیش از شروع، اطلاعات هر دو سرور را بررسی کنید. منابع موجود بازنویسی نمی‌شوند.",
  ],
  pairFormHelp: [
    "Choose the method and two different servers. Required engines must already be installed.",
    "روش اتصال و دو سرور متفاوت را انتخاب کنید. موتورهای لازم باید از قبل نصب شده باشند.",
  ],
  pairAutoName: ["Automatic name", "نام خودکار"],
  pairStart: ["Check and create", "بررسی و ساخت"],
  pairConfirm: ["Connection works — keep it", "اتصال درست است؛ نگه‌دار"],
  pairRollback: ["Cancel and remove new resources", "لغو و حذف منابع جدید"],
  pairRetryRecovery: ["Retry safe recovery", "تلاش دوباره برای بازیابی امن"],
  pairLeaseUntil: ["Confirm before", "مهلت تأیید تا"],
  pairEnableHelp: [
    "Requires two online servers with paired operations enabled. Install the remote Agent with --operations.",
    "دو سرور آنلاین با قابلیت اجرای عملیات لازم است. ایجنت سرور مقابل را با گزینهٔ ‎--operations نصب کنید.",
  ],
  pairSafetyHelp: [
    "Check connectivity yourself, then confirm within five minutes of the first apply. Without confirmation, each broker attempts to remove its unchanged new resource. Interrupted or changed resources need inspection; this is not an atomic two-server transaction.",
    "ارتباط را خودتان بررسی و حداکثر تا پنج دقیقه پس از اولین اجرا تأیید کنید. بدون تأیید، بروکر هر سمت برای حذف منبع جدید و تغییرنکردهٔ خود اقدام می‌کند. توقف ناگهانی یا تغییر دستی نیاز به بررسی دارد؛ عملیات دو سرور اتمیک نیست.",
  ],
  pairGREHelp: [
    "Allow GRE protocol 47 between both servers. Entrance uses the existing Iran role; destination uses Kharej. No default routes or firewall policies are changed.",
    "پروتکل GRE با شمارهٔ 47 باید بین دو سرور مجاز باشد. ورودی از نقش فعلی ایران و مقصد از نقش خارج استفاده می‌کند. مسیر پیش‌فرض و سیاست فایروال تغییر نمی‌کند.",
  ],
  pairFRPHelp: [
    "Allow the control and public service ports. A private shared token is generated automatically. This FRP preset uses TLS and token authentication; custom CA verification and WSS are not included.",
    "پورت ارتباط دو سرور و پورت کاربران باید مجاز باشند. توکن مشترک خودکار ساخته می‌شود. این حالت FRP از TLS و احراز هویت توکن استفاده می‌کند؛ تأیید CA سفارشی و WSS در این مسیر موجود نیست.",
  ],
  os: ["Operating system", "سیستم‌عامل"],
  localInventoryError: [
    "Local inventory could not be read. Check the panel broker and saved manager state.",
    "اطلاعات محلی خوانده نشد. بروکر پنل و تنظیمات ذخیره‌شدهٔ پروژه را بررسی کنید.",
  ],
  nodesSubtitle: [
    "Your panel host and connected servers, in one place.",
    "سرور پنل و سرورهای متصل را یک‌جا ببینید.",
  ],
  addNode: ["Add server", "افزودن سرور"],
  localReady: [
    "Your local server is already available",
    "سرور فعلی از قبل در دسترس است",
  ],
  setupGuide: ["Setup guide", "راهنمای راه‌اندازی"],
  controllerEndpoint: ["Agent connection address", "آدرس اتصال ایجنت"],
  node_revoked: ["Access revoked", "دسترسی لغو شده"],
  localNode: [
    "Local server · no Agent needed",
    "سرور محلی · بدون نیاز به ایجنت",
  ],
  remoteNode: [
    "Remote server · outbound Agent",
    "سرور دیگر · اتصال از طریق ایجنت",
  ],
  lastSeen: ["Last contact", "آخرین ارتباط"],
  inventoryObserved: ["Inventory collected", "زمان دریافت اطلاعات"],
  notReported: ["Not reported yet", "هنوز دریافت نشده"],
  nodeWaitingHelp: [
    "Waiting for a valid inventory report. Install or start the Agent on this server.",
    "هنوز اطلاعاتی دریافت نشده است. ایجنت را روی این سرور نصب یا اجرا کنید.",
  ],
  nodeOfflineHelp: [
    "No contact for over three minutes. The inventory below is an older snapshot; tunnels may still be running.",
    "بیش از سه دقیقه ارتباطی نبوده است. اطلاعات نمایش‌داده‌شده قدیمی است؛ تونل‌ها ممکن است همچنان فعال باشند.",
  ],
  nodeInventoryError: [
    "Agent connected, but its local inventory could not be read. Previous inventory, when present, stays visible with its original time.",
    "ایجنت وصل شده، اما اطلاعات محلی خوانده نشده است. اطلاعات قبلی با زمان اصلی خودش نمایش داده می‌شود.",
  ],
  nodeDetails: ["View details", "جزئیات سرور"],
  revokeNode: ["Revoke access", "لغو دسترسی"],
  revokeNodeHelp: [
    "This immediately blocks this Agent's reports and certificate renewal. It does not stop or delete any tunnel. Reconnecting requires a new invitation and identity.",
    "دریافت اطلاعات و تمدید گواهی این ایجنت فوراً مسدود می‌شود. هیچ تونلی متوقف یا حذف نمی‌شود. اتصال مجدد به کد و هویت جدید نیاز دارد.",
  ],
  nodeNameHelp: [
    "Choose a recognizable name, such as Tehran entrance or Frankfurt exit.",
    "نامی مشخص انتخاب کنید؛ مثلاً ورودی تهران یا خروجی فرانکفورت.",
  ],
  createInvitation: ["Create enrollment code", "ساخت کد اتصال"],
  inviteSecretHelp: [
    "Valid for ten minutes and one enrollment. Keep this code private; closing this dialog clears it.",
    "کد ده دقیقه اعتبار دارد و فقط یک‌بار قابل استفاده است. محرمانه نگه دارید؛ با بستن پنجره پاک می‌شود.",
  ],
  enrollmentCode: ["One-time enrollment code", "کد اتصال یک‌بارمصرف"],
  expires: ["Expires", "پایان اعتبار"],
  invitationHttpHelp: [
    "This browser connection is HTTP. Use a trusted private path or HTTPS when handling enrollment codes; Agent transport itself always uses TLS.",
    "ارتباط مرورگر HTTP است. کد اتصال را از مسیر خصوصی مطمئن یا HTTPS دریافت کنید؛ ارتباط خود ایجنت همیشه رمزگذاری شده است.",
  ],
  agentPackageNotice: [
    `Use a matching v${panelVersion} Agent package. For offline packages, add --package-dir; see the guide.`,
    `برای ایجنت از بستهٔ هماهنگ نسخهٔ ${panelVersion} استفاده کنید. برای نصب آفلاین، گزینهٔ ‎--package-dir را اضافه کنید؛ راهنما را ببینید.`,
  ],
  manualCopyHelp: [
    "Run the installer on the other server, then paste this code at its hidden prompt. If clipboard access is unavailable, select and copy the code manually.",
    "نصب‌کننده را روی سرور دیگر اجرا کنید و کد را در ورودی مخفی بچسبانید. اگر کپی خودکار کار نکرد، متن کد را انتخاب و دستی کپی کنید.",
  ],
  nodeDetailHelp: [
    "Latest inventory and optional traffic snapshots. Service status belongs to the reported time.",
    "آخرین گزارش اتصال‌ها و مصرف اختیاری؛ وضعیت سرویس به زمان ثبت گزارش مربوط است.",
  ],
  nodeIdentity: ["Stable node ID", "شناسهٔ ثابت سرور"],
  nodeGuide: ["Servers and Agents", "راهنمای سرورها و ایجنت‌ها"],
  nodeGuideIntro: [
    "Three steps to connect another server. Your local server is ready now.",
    "سرور فعلی آماده است. برای اتصال سرور دیگر، این سه مرحله را انجام دهید.",
  ],
  localGuide: [
    "The panel host is automatically listed. It may be your entrance, exit or a separate management server. Local tunnels work without enrollment or a third server.",
    "سرور پنل خودکار در فهرست است. می‌تواند ورودی، خروجی یا سرور جداگانهٔ مدیریت باشد. کار محلی به ثبت ایجنت یا سرور سوم نیاز ندارد.",
  ],
  nodeRecoveryGuide: [
    "Reports arrive about once a minute. Connection loss uses bounded retry delays; tunnels remain independent. Check the Agent and its read-only broker services, DNS, clock and control-port access. Certificates renew automatically while connected; after a 30-day expiry or revocation, use a fresh identity and invitation. Controller restarts clear cached inventory until the next report.",
    "گزارش‌ها حدود هر دقیقه می‌رسند. پس از قطع ارتباط تلاش مجدد انجام می‌شود و تونل‌ها مستقل می‌مانند. سرویس ایجنت و بروکر فقط‌خواندنی، DNS، ساعت و دسترسی پورت کنترل را بررسی کنید. گواهی در زمان اتصال خودکار تمدید می‌شود؛ پس از انقضای سی‌روزه یا لغو دسترسی، هویت و کد جدید لازم است. با راه‌اندازی مجدد پنل، اطلاعات موقت تا گزارش بعدی خالی می‌شود.",
  ],
  nodeRefreshHelp: [
    "Refresh to fetch the latest received inventory.",
    "برای دیدن آخرین اطلاعات دریافتی، تازه‌سازی کنید.",
  ],
  nodeBoundsHelp: [
    "Up to 64 identities and 256 KiB per report. Inventory remains a manually refreshed snapshot. Only active pair jobs poll every two seconds in this page. Opted-in Agents pull work every five to six seconds; inventory still reports about once a minute.",
    "حداکثر 64 هویت و 256 کیلوبایت برای هر گزارش. اطلاعات سرورها دستی تازه‌سازی می‌شود. فقط عملیات فعال این صفحه هر دو ثانیه بررسی می‌شود. ایجنت مجاز هر پنج تا شش ثانیه کار جدید می‌گیرد؛ اطلاعات سرور همچنان حدود هر دقیقه گزارش می‌شود.",
  ],
} satisfies Messages;
