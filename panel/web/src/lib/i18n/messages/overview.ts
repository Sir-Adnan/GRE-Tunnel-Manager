// Overview page: host status, live telemetry and the attention list.
import type { Messages } from "./types";

export const overview = {
  serverLive: ["Server activity", "وضعیت لحظه‌ای سرور"],
  live: ["Live", "زنده"],
  serverLiveHelp: [
    "CPU, memory and network rates come from Linux counters. Rates are averages between samples, not tunnel totals. Only default-route interfaces are counted to avoid adding inner and outer tunnel traffic together. Updates stop when this page is hidden or closed; no history is written to disk.",
    "مصرف پردازنده، رم و سرعت شبکه از شمارنده‌های لینوکس خوانده می‌شود. سرعت‌ها میانگین بین دو نمونه‌اند و مصرف کل تونل نیستند. فقط رابط‌های مسیر پیش‌فرض شمرده می‌شوند تا ترافیک داخلی و بیرونی تونل با هم جمع نشود. با پنهان یا بسته شدن صفحه، به‌روزرسانی متوقف می‌شود و تاریخچه‌ای روی دیسک ذخیره نمی‌شود.",
  ],
  cpuUsage: ["CPU", "پردازنده"],
  allCPUCores: ["Across all cores", "مجموع همهٔ هسته‌ها"],
  networkReceive: ["Receive rate", "سرعت دریافت"],
  networkSend: ["Send rate", "سرعت ارسال"],
  defaultRouteInterfaces: ["Network interfaces:", "رابط‌های شبکه:"],
  pauseLive: ["Pause", "توقف نمایش زنده"],
  resumeLive: ["Resume", "ادامهٔ نمایش زنده"],
  livePaused: ["Paused", "متوقف"],
  liveUnavailable: ["Unavailable", "در دسترس نیست"],
  livePartial: [
    "Some host counters are unavailable. Available readings are still shown.",
    "بعضی شمارنده‌های سرور در دسترس نیستند. مقدارهای موجود همچنان نمایش داده می‌شوند.",
  ],
  liveInterval: [
    "Live update interval (1 s is the finest useful step)",
    "فاصلهٔ به‌روزرسانی زنده (کمترین گام مفید 1 ثانیه است)",
  ],
  memory: ["Server memory", "حافظهٔ سرور"],
  allHealthy: ["All services healthy", "همهٔ سرویس‌ها سالم‌اند"],
  allHealthyHelp: [
    "No enabled service has failed or stopped, and every engine in use is installed.",
    "هیچ سرویس فعالی خطا نداده یا متوقف نشده و همهٔ موتورهای در حال استفاده نصب‌اند.",
  ],
  engineMissing: ["Engine not installed", "موتور نصب نیست"],
  managed: ["Managed connections", "اتصال‌های مدیریت‌شده"],
  services: ["Running services", "سرویس‌های فعال"],
  uptime: ["Server uptime", "مدت روشن‌بودن سرور"],
  seeAll: ["View all", "مشاهدهٔ همه"],
  servicesRunning: [
    "Running of enabled services",
    "در حال اجرا از سرویس‌های فعال",
  ],
  reviewIssues: ["Review the list below", "فهرست پایین را بررسی کنید"],
  load: ["Load", "بار"],
} satisfies Messages;
