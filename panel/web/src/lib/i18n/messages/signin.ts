import type { Messages } from "./types";

/** Sign-in security, panel updates and the getting-started checklist. */
export const signin = {
  settingsUpdates: ["Updates", "به‌روزرسانی"],
  updatesTitle: ["Panel updates", "به‌روزرسانی پنل"],
  updatesIntro: [
    "The server checks for a new release once a day. Installing is always your choice.",
    "سرور روزی یک بار نسخهٔ جدید را بررسی می‌کند. نصب همیشه با انتخاب شماست.",
  ],
  updateAvailable: ["v{version} is available", "نسخهٔ v{version} آماده است"],
  updateAvailableHelp: [
    "Tunnels keep running. The panel restarts for about ten seconds and you sign in again. If the new release does not start, this one is restored.",
    "تونل‌ها کار می‌کنند. پنل حدود ده ثانیه دوباره راه‌اندازی می‌شود و باید دوباره وارد شوید. اگر نسخهٔ جدید بالا نیاید، همین نسخه برمی‌گردد.",
  ],
  updateLatest: ["This is the latest release", "این آخرین نسخه است"],
  updateLatestHelp: [
    "Nothing to install. Check now to ask the release server again.",
    "چیزی برای نصب نیست. با «بررسی همین حالا» دوباره از سرور انتشار بپرسید.",
  ],
  updateNotChecked: ["Not checked yet", "هنوز بررسی نشده"],
  updateInstalled: ["Installed", "نسخهٔ نصب‌شده"],
  updateLatestRelease: ["Latest release", "آخرین انتشار"],
  updateReleaseNotes: ["release notes", "یادداشت‌های انتشار"],
  updateChecked: ["Last checked", "آخرین بررسی"],
  updateCheckError: ["Last check failed", "خطای آخرین بررسی"],
  updateTo: ["Update to v{version}", "به‌روزرسانی به v{version}"],
  updateCheckNow: ["Check now", "بررسی همین حالا"],
  updateConfirmTitle: [
    "Update to v{version}?",
    "به v{version} به‌روزرسانی شود؟",
  ],
  updateConfirmBody: [
    "The server downloads and verifies the release, then restarts the panel. Tunnels keep running. Keep this page open; it reloads when the new panel is ready, and you sign in again.",
    "سرور نسخه را دانلود و بررسی می‌کند و پنل را دوباره راه‌اندازی می‌کند. تونل‌ها کار می‌کنند. این صفحه را باز نگه دارید؛ وقتی پنل جدید آماده شد دوباره بارگذاری می‌شود و باید دوباره وارد شوید.",
  ],
  updateNow: ["Update now", "به‌روزرسانی همین حالا"],
  updateRunning: [
    "Updating to v{version}…",
    "در حال به‌روزرسانی به v{version}…",
  ],
  updateRunningHelp: [
    "Downloading, verifying and restarting. This page reloads by itself; tunnels keep running.",
    "دانلود، بررسی و راه‌اندازی دوباره. این صفحه خودش دوباره بارگذاری می‌شود؛ تونل‌ها کار می‌کنند.",
  ],
  updateDone: ["Updated to v{version}.", "به v{version} به‌روزرسانی شد."],
  updateFailedTitle: ["Update did not finish.", "به‌روزرسانی کامل نشد."],
  updateFailed: [
    "The update did not finish; the installed release keeps running. See gtm logs update on the server.",
    "به‌روزرسانی کامل نشد؛ نسخهٔ نصب‌شده کار می‌کند. روی سرور gtm logs update را ببینید.",
  ],
  updateLastFailed: [
    "The update started on {date} did not finish; the previous release was kept.",
    "به‌روزرسانی شروع‌شده در {date} کامل نشد؛ نسخهٔ قبلی حفظ شد.",
  ],
  updateTerminal: ["Update from the terminal", "به‌روزرسانی از ترمینال"],
  updateTerminalHelp: [
    "The same update over SSH, with progress on screen.",
    "همین به‌روزرسانی از طریق SSH، با نمایش مراحل.",
  ],
  updateSidebar: ["v{version} available", "v{version} آماده است"],

  signInTitle: ["Sign-in", "ورود به پنل"],
  signInIntro: [
    "Two-factor sign-in, signed-in browsers and the account password.",
    "ورود دومرحله‌ای، مرورگرهای واردشده و رمز حساب.",
  ],
  twoFactorOn: ["Two-factor sign-in is on", "ورود دومرحله‌ای روشن است"],
  twoFactorOff: ["Two-factor sign-in is off", "ورود دومرحله‌ای خاموش است"],
  twoFactorOnHelp: [
    "Sign-in asks for a code from your authenticator app. {count} recovery codes left.",
    "ورود، کدی از اپ Authenticator شما می‌خواهد. {count} کد بازیابی باقی مانده است.",
  ],
  twoFactorOffHelp: [
    "A leaked password alone is enough to sign in. Add a code from an authenticator app such as Google Authenticator, Aegis or 1Password.",
    "با لو رفتن رمز به‌تنهایی می‌توان وارد شد. کدی از یک اپ Authenticator مثل Google Authenticator، Aegis یا 1Password اضافه کنید.",
  ],
  twoFactorTurnOn: ["Turn on", "روشن کردن"],
  twoFactorTurnOff: ["Turn off", "خاموش کردن"],
  twoFactorFewCodes: [
    "Few recovery codes are left. Turn two-factor sign-in off and on again to get new ones.",
    "کدهای بازیابی کمی مانده است. برای گرفتن کدهای جدید، ورود دومرحله‌ای را خاموش و دوباره روشن کنید.",
  ],
  twoFactorSetupTitle: [
    "Set up two-factor sign-in",
    "راه‌اندازی ورود دومرحله‌ای",
  ],
  twoFactorSetupHelp: [
    "Scan the code with your authenticator app, then enter the six-digit code it shows.",
    "کد را با اپ Authenticator اسکن کنید و کد شش‌رقمی‌ای را که نشان می‌دهد وارد کنید.",
  ],
  twoFactorQR: [
    "QR code for the authenticator app",
    "کد QR برای اپ Authenticator",
  ],
  twoFactorManual: [
    "Cannot scan? Add this key by hand (time-based, six digits).",
    "اسکن نمی‌شود؟ این کلید را دستی اضافه کنید (مبتنی بر زمان، شش رقم).",
  ],
  twoFactorCopySecret: ["Copy key", "کپی کلید"],
  twoFactorCode: ["Code from the app", "کد اپ"],
  twoFactorCodeHelp: [
    "Codes change every 30 seconds. The server clock must be correct.",
    "کدها هر 30 ثانیه عوض می‌شوند. ساعت سرور باید درست باشد.",
  ],
  twoFactorCodeInvalid: ["Enter the six digits.", "شش رقم را وارد کنید."],
  twoFactorVerify: ["Verify and turn on", "بررسی و روشن کردن"],
  twoFactorCodesTitle: [
    "Save your recovery codes",
    "کدهای بازیابی را ذخیره کنید",
  ],
  twoFactorCodesHelp: [
    "Each code signs in once if you lose your phone. They are shown only now.",
    "اگر گوشی را گم کنید، هر کد یک بار برای ورود کار می‌کند. فقط همین حالا نمایش داده می‌شوند.",
  ],
  twoFactorCopyCodes: ["Copy codes", "کپی کدها"],
  twoFactorDownloadCodes: ["Download .txt", "دانلود .txt"],
  twoFactorSaved: ["I saved these codes", "این کدها را ذخیره کردم"],
  twoFactorFileHeader: [
    "GRE Tunnel Manager recovery codes (each works once)",
    "GRE Tunnel Manager recovery codes (each works once)",
  ],
  twoFactorDisableTitle: [
    "Turn off two-factor sign-in?",
    "ورود دومرحله‌ای خاموش شود؟",
  ],
  twoFactorDisableHelp: [
    "Confirm with your password and a code from the app or a recovery code. Lost both? Run sudo gtm 2fa off on the server.",
    "با رمز و یک کد از اپ یا یک کد بازیابی تأیید کنید. هر دو را ندارید؟ روی سرور sudo gtm 2fa off را اجرا کنید.",
  ],
  twoFactorCodeOrRecovery: ["App code or recovery code", "کد اپ یا کد بازیابی"],
  twoFactorDisableMissing: [
    "Enter your password and a code.",
    "رمز و یک کد را وارد کنید.",
  ],
  twoFactorDisabled: [
    "Two-factor sign-in is off.",
    "ورود دومرحله‌ای خاموش شد.",
  ],
  sessionsTitle: ["Signed-in browsers", "مرورگرهای واردشده"],
  sessionsRevokeOthers: ["Sign out all others", "خروج همهٔ بقیه"],
  sessionsRevokedOthers: [
    "Other browsers were signed out.",
    "مرورگرهای دیگر خارج شدند.",
  ],
  sessionRevoke: ["Sign out", "خروج"],
  sessionRevoked: ["That browser was signed out.", "آن مرورگر خارج شد."],
  sessionThisBrowser: ["This browser", "همین مرورگر"],
  sessionUnknownBrowser: ["Unknown browser", "مرورگر ناشناخته"],
  sessionLastActive: ["active {date}", "فعال {date}"],
  sessionsHelp: [
    "Sessions end after four hours, and all of them when the panel restarts or the password changes.",
    "نشست‌ها پس از چهار ساعت تمام می‌شوند و با راه‌اندازی دوبارهٔ پنل یا تغییر رمز، همه خارج می‌شوند.",
  ],
  loginCode: ["Authentication code", "کد تأیید"],
  loginCodeHelp: [
    "Enter the six-digit code from your authenticator app, or a recovery code.",
    "کد شش‌رقمی اپ Authenticator یا یک کد بازیابی را وارد کنید.",
  ],
  loginCodeBack: ["Use another account", "حساب دیگر"],

  startTitle: ["Get started", "شروع کار"],
  startProgress: ["{done} of {total} done", "{done} از {total} انجام شده"],
  startHide: ["Hide the checklist", "پنهان کردن چک‌لیست"],
  startDone: ["done", "انجام شده"],
  startSetUp: ["Set up", "تنظیم"],
  start_https: [
    "Use a trusted HTTPS certificate",
    "استفاده از گواهی HTTPS معتبر",
  ],
  start_httpsHelp: [
    "Free from Let's Encrypt for a domain or the server IP; renewed automatically.",
    "رایگان از Let's Encrypt برای دامنه یا آی‌پی سرور؛ با تمدید خودکار.",
  ],
  start_twoFactor: ["Turn on two-factor sign-in", "روشن کردن ورود دومرحله‌ای"],
  start_twoFactorHelp: [
    "A code from your phone, so a leaked password is not enough.",
    "کدی از گوشی شما، تا لو رفتن رمز کافی نباشد.",
  ],
  start_connection: ["Create the first connection", "ساخت اولین اتصال"],
  start_connectionHelp: [
    "Forward a port to a destination server, or build a GRE tunnel.",
    "یک پورت را به سرور مقصد فوروارد کنید یا یک تونل GRE بسازید.",
  ],
  start_health: ["Turn on health monitoring", "روشن کردن پایش سلامت"],
  start_healthHelp: [
    "Probe destinations and see outages before users report them.",
    "مقصدها را بررسی کنید و قطعی‌ها را پیش از گزارش کاربران ببینید.",
  ],
  start_backups: ["Schedule automatic backups", "زمان‌بندی پشتیبان خودکار"],
  start_backupsHelp: [
    "Daily or weekly snapshots of every connection and setting.",
    "نسخهٔ روزانه یا هفتگی از همهٔ اتصال‌ها و تنظیمات.",
  ],
  start_alerts: [
    "Get alerts on Telegram or a webhook",
    "دریافت هشدار در تلگرام یا وب‌هوک",
  ],
  start_alertsHelp: [
    "Hear about outages, failed renewals and maintenance results.",
    "از قطعی‌ها، تمدیدهای ناموفق و نتیجهٔ نگهداری باخبر شوید.",
  ],
} satisfies Messages;
