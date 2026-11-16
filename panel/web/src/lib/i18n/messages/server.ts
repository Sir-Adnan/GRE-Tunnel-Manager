import type { Messages } from "./types";

/** The panel's own server answers; see lib/server-messages.ts. */
export const server = {
  srvNotFound: ["Not found", "پیدا نشد"],
  srvNodeNotFound: [
    "That Node no longer exists; reload the list",
    "این Node دیگر وجود ندارد؛ فهرست را دوباره بارگذاری کنید",
  ],
  srvJobNotFound: [
    "That task is no longer tracked; reload the page",
    "این کار دیگر پیگیری نمی‌شود؛ صفحه را دوباره بارگذاری کنید",
  ],
  srvBusy: [
    "The panel is busy; try again in a moment",
    "پنل مشغول است؛ چند لحظه بعد دوباره امتحان کنید",
  ],
  srvInvalidRequest: [
    "The panel did not accept this request; reload the page and try again",
    "پنل این درخواست را نپذیرفت؛ صفحه را دوباره بارگذاری و امتحان کنید",
  ],
  srvBroker: [
    "The panel service gave an unexpected answer; check gtm logs broker",
    "سرویس پنل پاسخ غیرمنتظره داد؛ gtm logs broker را بررسی کنید",
  ],
  srvMetrics: [
    "Server metrics are not available right now",
    "آمار سرور فعلاً در دسترس نیست",
  ],
  srvSignIn: [
    "Your session ended; sign in again",
    "نشست شما تمام شد؛ دوباره وارد شوید",
  ],
  srvSecurityCheck: [
    "The request failed a security check; reload the page",
    "درخواست از بررسی امنیتی رد شد؛ صفحه را دوباره بارگذاری کنید",
  ],
  srvOperationRunning: [
    "Another task is running; wait for it to finish",
    "کار دیگری در حال اجراست؛ صبر کنید تمام شود",
  ],
  srvUnreachable: [
    "Could not reach the panel; check the connection and try again",
    "به پنل دسترسی نشد؛ اتصال را بررسی و دوباره امتحان کنید",
  ],
  srvCredentials: [
    "Incorrect username or password",
    "نام کاربری یا رمز عبور نادرست است",
  ],
  srvThrottled: [
    "Too many sign-in attempts; try again in 5 minutes",
    "تلاش‌های ورود زیاد بود؛ 5 دقیقه دیگر دوباره امتحان کنید",
  ],
  srvTooManySessions: [
    "Too many signed-in browsers; sign out of one under Settings → Security",
    "مرورگرهای واردشده زیادند؛ از تنظیمات ← امنیت یکی را خارج کنید",
  ],
  srvCodeRequired: [
    "Enter the code from your authenticator app",
    "کد برنامهٔ احراز هویت را وارد کنید",
  ],
  srvIncorrectCode: [
    "Incorrect code; enter the current code or a recovery code",
    "کد نادرست است؛ کد فعلی یا یک کد بازیابی را وارد کنید",
  ],
  srvIncorrectPassword: ["Incorrect password", "رمز عبور نادرست است"],
  srvIncorrectPasswordOrCode: [
    "Incorrect password or code",
    "رمز عبور یا کد نادرست است",
  ],
  srvTwoFactorOn: [
    "Two-factor sign-in is already on; turn it off first",
    "ورود دومرحله‌ای از قبل روشن است؛ اول آن را خاموش کنید",
  ],
  srvSetupExpired: [
    "The setup expired; start again",
    "زمان راه‌اندازی تمام شد؛ از اول شروع کنید",
  ],
  srvCodeMismatch: [
    "The code does not match; check the time on your phone and try the next code",
    "کد مطابقت ندارد؛ ساعت گوشی را بررسی و کد بعدی را امتحان کنید",
  ],
  srvSetupFailed: [
    "Could not prepare two-factor sign-in; try again",
    "آماده‌سازی ورود دومرحله‌ای انجام نشد؛ دوباره امتحان کنید",
  ],
  srvSessionEnded: [
    "That session has already ended",
    "این نشست از قبل تمام شده است",
  ],
  srvEmail: [
    "Enter a valid email address or leave it empty",
    "یک ایمیل معتبر وارد کنید یا خالی بگذارید",
  ],
  srvReloadHTTPS: [
    "Certificate reload works on the HTTPS panel only",
    "بارگذاری دوبارهٔ گواهی فقط روی پنل HTTPS کار می‌کند",
  ],
  srvReloadFailed: [
    "The certificate could not be reloaded; the previous one stays in use. Check the certificate files and public host.",
    "گواهی دوباره بارگذاری نشد و گواهی قبلی در حال استفاده است. فایل‌های گواهی و آدرس عمومی را بررسی کنید.",
  ],
  srvUpdateUnavailable: [
    "Update checks are not available on this panel",
    "بررسی به‌روزرسانی روی این پنل در دسترس نیست",
  ],
  srvUpdateRunning: [
    "An update is already running",
    "یک به‌روزرسانی در حال اجراست",
  ],
  srvUpdateNone: [
    "No newer release is known; check for updates first",
    "نسخهٔ جدیدتری شناخته نشده؛ اول بررسی کنید",
  ],
  srvReleaseServer: [
    "Could not reach the release server ({e})",
    "به سرور انتشار دسترسی نشد ({e})",
  ],
  srvUpdateStart: [
    "The update could not start: {e}",
    "به‌روزرسانی شروع نشد: {e}",
  ],
} satisfies Messages;
