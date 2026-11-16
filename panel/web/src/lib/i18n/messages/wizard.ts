import type { Messages } from "./types";

/** The two-server setup wizard (GRE tunnel plus a forward through it). */
export const wizard = {
  wizOpen: ["Two servers", "دو سرور"],
  wizOpenHelp: [
    "Connect this server to a foreign server with a GRE tunnel and forward ports through it",
    "این سرور را با تونل GRE به یک سرور خارج وصل کنید و پورت‌ها را از آن عبور دهید",
  ],
  wizTitle: ["Tunnel to a foreign server", "تونل به سرور خارج"],
  wizIntro: [
    "Users connect to this server; their traffic travels through a GRE tunnel to the foreign server.",
    "کاربران به این سرور وصل می‌شوند و ترافیک از راه یک تونل GRE به سرور خارج می‌رود.",
  ],
  wizStepTunnel: ["Tunnel", "تونل"],
  wizStepForward: ["Ports", "پورت‌ها"],
  wizStepReview: ["Review", "بازبینی"],
  wizRemote: ["Foreign server IP", "آی‌پی سرور خارج"],
  wizRemoteHelp: [
    "The public address of the server your service runs on.",
    "آدرس عمومی سروری که سرویس شما روی آن اجرا می‌شود.",
  ],
  wizBind: ["This server's IP", "آی‌پی این سرور"],
  wizBindHelp: [
    "The address the foreign server will reach this one at.",
    "آدرسی که سرور خارج با آن به این سرور می‌رسد.",
  ],
  wizIDHelp: [
    "The lowest free ID is chosen. Both servers use the same ID.",
    "کوچک‌ترین شناسهٔ آزاد انتخاب شده است. هر دو سرور از یک شناسه استفاده می‌کنند.",
  ],
  wizMTUHelp: [
    "1430 suits most links. At most {max}.",
    "1430 برای بیشتر مسیرها مناسب است. حداکثر {max}.",
  ],
  wizForward: ["Forward ports through the tunnel", "عبور پورت‌ها از تونل"],
  wizForwardHelp: [
    "Turn off to create the tunnel only and add connections later.",
    "خاموش کنید تا فقط تونل ساخته شود و اتصال‌ها را بعداً اضافه کنید.",
  ],
  wizPorts: ["Public ports", "پورت‌های عمومی"],
  wizPortsHelp: [
    "One port, a list or a range, such as 443, 8443 or 2000-2100. The foreign server receives the same port numbers.",
    "یک پورت، فهرست یا بازه؛ مثل 443، 8443 یا 2000-2100. سرور خارج همان شماره‌پورت‌ها را دریافت می‌کند.",
  ],
  wizCreate: ["Create", "ساختن"],
  wizRetry: ["Try again", "تلاش دوباره"],
  wizOpenHealth: ["Open Health", "باز کردن سلامت"],
  wizTaskTunnel: ["GRE tunnel on this server", "تونل GRE روی این سرور"],
  wizTaskForward: ["Forward through the tunnel", "فوروارد از راه تونل"],
  wizTask_waiting: ["Waiting", "در انتظار"],
  wizTask_running: ["In progress", "در حال انجام"],
  wizTask_done: ["Done", "انجام شد"],
  wizTask_failed: ["Failed", "ناموفق"],
  wizTunnelFailed: [
    "The tunnel was not created; nothing changed.",
    "تونل ساخته نشد و چیزی تغییر نکرد.",
  ],
  wizForwardFailed: [
    "The tunnel is ready, but the forward was not created. Fix the cause and try again; the tunnel is kept.",
    "تونل آماده است ولی فوروارد ساخته نشد. علت را برطرف و دوباره امتحان کنید؛ تونل حفظ می‌شود.",
  ],
  wizDone: [
    "Done on this server. The tunnel comes up once the foreign server has the matching settings below.",
    "روی این سرور انجام شد. تونل وقتی برقرار می‌شود که سرور خارج تنظیمات متناظر پایین را داشته باشد.",
  ],
  wizRoute: ["Route", "مسیر"],
  wizHopUsers: ["Users", "کاربران"],
  wizHopHere: ["This server", "این سرور"],
  wizHopForeign: ["Foreign server", "سرور خارج"],
  wizRouteForward: [
    "Ports {ports} on this server go through the tunnel to {ip}, the same ports on the foreign server.",
    "پورت‌های {ports} این سرور از راه تونل به {ip}، یعنی همان پورت‌ها روی سرور خارج، می‌روند.",
  ],
  wizRouteTunnelOnly: [
    "Only the tunnel is created. Use the GRE template in a new connection to forward ports later.",
    "فقط تونل ساخته می‌شود. بعداً با قالب GRE در اتصال جدید پورت‌ها را عبور دهید.",
  ],
  wizFarTitle: ["On the foreign server", "روی سرور خارج"],
  wizFarInstall: [
    "Install the panel there if it is not installed yet:",
    "اگر پنل آن‌جا نصب نیست، نصبش کنید:",
  ],
  wizFarGRE: [
    "In its panel open GRE → Add and enter these values:",
    "در پنل آن از بخش GRE گزینهٔ افزودن را بزنید و این مقادیر را وارد کنید:",
  ],
  wizFarFirewall: [
    "Allow IP protocol 47 (GRE) between the two servers, including any provider firewall.",
    "پروتکل IP شمارهٔ 47 (GRE) را بین دو سرور، از جمله در فایروال ارائه‌دهنده، باز کنید.",
  ],
  wizCopy: ["Copy {name}", "کپی {name}"],
  wizErrorAddress: [
    "Enter an IPv4 or IPv6 address",
    "یک آدرس IPv4 یا IPv6 وارد کنید",
  ],
  wizErrorSameServer: [
    "This is this server's own address; enter the foreign server",
    "این آدرس خودِ این سرور است؛ آدرس سرور خارج را وارد کنید",
  ],
  wizErrorFamily: [
    "Both addresses must be IPv4, or both IPv6",
    "هر دو آدرس باید IPv4 یا هر دو IPv6 باشند",
  ],
  wizErrorID: ["Enter a number from 1 to 250", "عددی از 1 تا 250 وارد کنید"],
  wizErrorIDUsed: [
    "A tunnel with this ID already exists on this server",
    "تونلی با این شناسه روی این سرور وجود دارد",
  ],
  wizErrorMTU: [
    "Enter an MTU from 1280 to the maximum shown",
    "MTU را از 1280 تا حداکثر نشان‌داده‌شده وارد کنید",
  ],
  wizNameHelp: [
    "Up to 40 English letters, digits, spaces, dots, dashes or underscores.",
    "حداکثر 40 نویسه از حروف انگلیسی، رقم، فاصله، نقطه، خط تیره یا زیرخط.",
  ],
  wizErrorName: [
    "Use only English letters, digits, spaces, dots, dashes or underscores (at most 40)",
    "فقط حروف انگلیسی، رقم، فاصله، نقطه، خط تیره یا زیرخط (حداکثر 40)",
  ],
  wizErrorPortUsed: [
    "A connection already uses one of these ports",
    "یک اتصال از یکی از این پورت‌ها استفاده می‌کند",
  ],
} satisfies Messages;
