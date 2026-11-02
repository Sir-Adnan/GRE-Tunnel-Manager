// Settings, appearance and engine components.
import type { Messages } from "./types";

export const system = {
  engineMaintenance: ["Versions & updates", "نسخه‌ها و به‌روزرسانی"],
  engineMaintenanceHelp: [
    "Check only when needed; results are cached for 5 minutes. Binary engines use official GitHub releases and only verified, checksum-pinned versions can be installed. System packages use your distribution's existing package metadata. Newer upstream releases may need an adapter update first.",
    "بررسی با درخواست شما انجام می‌شود و نتیجه تا 5 دقیقه نگه داشته می‌شود. نسخهٔ رسمی موتورهای باینری از گیت‌هاب خوانده می‌شود، اما نصب فقط برای نسخهٔ بررسی‌شده با هش ثابت مجاز است. بسته‌های سیستم از اطلاعات مخزن فعلی توزیع استفاده می‌کنند. ممکن است نسخهٔ جدید بالادستی ابتدا به سازگاری در پنل نیاز داشته باشد.",
  ],
  checkEngineUpdates: ["Check versions", "بررسی نسخه‌ها"],
  updateEngine: ["Update engine", "به‌روزرسانی موتور"],
  officialRelease: ["Official releases", "نسخهٔ رسمی"],
  distributionCandidate: ["Repository candidate", "نسخهٔ مخزن"],
  latestRelease: ["Latest stable", "آخرین نسخهٔ پایدار"],
  verifiedVersion: ["Verified by this manager", "نسخهٔ سازگار با پنل"],
  officialSource: ["Official source", "منبع رسمی"],
  engineCheckFailed: [
    "The official source could not be checked. Try again later.",
    "بررسی منبع رسمی انجام نشد؛ کمی بعد دوباره تلاش کنید.",
  ],
  engineUpdateConfirm: [
    "Update this engine on the current server. Back up first. Package scripts may affect running services; existing binary processes may need an explicit restart later. Configurations are preserved, but peer compatibility and reconnecting clients must be checked.",
    "موتور همین سرور به‌روز می‌شود؛ ابتدا بکاپ بگیرید. نصب بسته ممکن است روی سرویس فعال اثر بگذارد؛ سرویس‌های باینری ممکن است بعداً به راه‌اندازی مجدد نیاز داشته باشند. تنظیمات حفظ می‌شوند، اما سازگاری دو سمت و اتصال دوبارهٔ کاربران را بررسی کنید.",
  ],
  installed: ["Installed", "نصب‌شده"],
  engineVersion: ["Detected version", "نسخهٔ شناسایی‌شده"],
  compatibility: ["Adapter compatibility", "سازگاری با مدیر تونل"],
  adapterDetails: ["Features and limits", "قابلیت‌ها و محدودیت‌ها"],
  configValidation: ["Configuration validation", "اعتبارسنجی تنظیمات"],
  signOut: ["Sign out", "خروج از حساب"],
  styleHelp: [
    "Choose a visual preset. Every preset supports light and dark mode and both languages.",
    "یک تم ظاهری انتخاب کنید. همهٔ تم‌ها حالت روشن و تیره و هر دو زبان را پشتیبانی می‌کنند.",
  ],
  appearanceDesc: [
    "A consistent experience, in your preferred language and style.",
    "زبان و ظاهر دلخواه، با تجربه‌ای یکپارچه.",
  ],
  autoRefresh: [
    "Auto-refresh while visible",
    "به‌روزرسانی خودکار در صفحهٔ باز",
  ],
  autoRefreshHelp: [
    "Refresh every 30 seconds; pauses when this tab is hidden.",
    "هر 30 ثانیه؛ با پنهان‌شدن تب متوقف می‌شود.",
  ],
  account: ["Account & access", "حساب و دسترسی"],
  passwordHelp: [
    "Reset credentials over SSH with: sudo gtm-panel reset-password; then restart the panel service.",
    "برای تغییر رمز، دستور زیر را در SSH اجرا کنید و سپس سرویس پنل را راه‌اندازی مجدد کنید.",
  ],
  exactTheme: [
    "Nettinx uses the original palette. Some original color pairs have limited contrast.",
    "رنگ‌های Nettinx مطابق تم اصلی هستند؛ کنتراست بعضی ترکیب‌ها محدود است.",
  ],
  componentsDesc: [
    "Install engines ahead of time. Installation does not create a tunnel.",
    "موتورها را از قبل نصب کنید؛ نصب به‌تنهایی تونلی ایجاد نمی‌کند.",
  ],
  notInstalled: ["Not installed", "نصب‌نشده"],
  installSelected: ["Install selected", "نصب موارد انتخابی"],
} satisfies Messages;
