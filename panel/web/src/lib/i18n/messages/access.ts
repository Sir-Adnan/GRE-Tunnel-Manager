import type { Messages } from "./types";

export const access = {
  tlsTitle: ["Panel connection security", "امنیت اتصال به پنل"],
  tlsIntro: [
    "Certificate status and renewal for this panel's browser connection.",
    "وضعیت گواهی و تمدید اتصال مرورگر به این پنل.",
  ],
  tlsState_http: ["HTTP connection", "اتصال HTTP"],
  tlsState_valid: ["Certificate is valid", "گواهی معتبر است"],
  tlsState_selfSigned: ["Self-signed certificate", "گواهی خودامضا"],
  tlsState_privateCA: [
    "Certificate requires client trust",
    "گواهی نیازمند اعتماد مرورگر است",
  ],
  tlsState_expiring: ["Renewal is due soon", "زمان تمدید نزدیک است"],
  tlsState_expired: ["Certificate has expired", "اعتبار گواهی تمام شده است"],
  tlsSelfSignedHelp: [
    "Traffic is encrypted. Verify the fingerprint through SSH before trusting the certificate.",
    "ترافیک رمزنگاری می‌شود. پیش از اعتماد به گواهی، اثر انگشت را از طریق SSH بررسی کنید.",
  ],
  tlsExternalHelp: [
    "Your ACME client manages issuance and renewal. The panel loads the validated certificate.",
    "ابزار ACME شما صدور و تمدید را انجام می‌دهد و پنل گواهی بررسی‌شده را بارگذاری می‌کند.",
  ],
  tlsHTTPHelp: [
    "Passwords and management requests are not encrypted on this browser connection. Use a trusted SSH tunnel or configure HTTPS.",
    "رمزها و درخواست‌های مدیریتی این اتصال مرورگر رمزنگاری نمی‌شوند. از تونل SSH مطمئن استفاده کنید یا HTTPS را تنظیم کنید.",
  ],
  tlsHost: ["Public host", "آدرس عمومی"],
  tlsExpires: ["Valid until", "معتبر تا"],
  tlsIssuer: ["Issued by", "صادرکننده"],
  tlsLoaded: ["Loaded by panel", "زمان بارگذاری در پنل"],
  tlsFingerprint: ["Certificate SHA-256", "اثر انگشت SHA-256 گواهی"],
  tlsReload: ["Reload certificate", "بارگذاری دوبارهٔ گواهی"],
  tlsReloaded: [
    "Certificate reloaded. New browser connections use the renewed certificate.",
    "گواهی دوباره بارگذاری شد. اتصال‌های جدید مرورگر از گواهی تمدیدشده استفاده می‌کنند.",
  ],
  tlsReloadHelp: [
    "Reload keeps sessions and tunnels running. Invalid renewals retain the previous certificate.",
    "بارگذاری دوباره، نشست‌ها و تونل‌ها را حفظ می‌کند. در صورت نامعتبر بودن گواهی جدید، گواهی قبلی باقی می‌ماند.",
  ],
  tlsRenewalGuide: ["Connect Certbot or acme.sh", "اتصال Certbot یا acme.sh"],
  tlsRenewalHelp: [
    "Issue the certificate with your ACME client first. Replace the example domain, then run this on the server through SSH.",
    "ابتدا گواهی را با ابزار ACME بگیرید. دامنهٔ نمونه را عوض کنید و سپس این دستور را از طریق SSH روی سرور اجرا کنید.",
  ],
  tlsRenewalHook: [
    "Use the same install command in the client's deploy hook after each successful renewal. The panel copies one private bundle and reloads only its public service. See docs/HTTPS.md for complete Certbot and acme.sh examples.",
    "همین دستور نصب را در deploy hook ابزار قرار دهید تا پس از هر تمدید موفق اجرا شود. پنل یک فایل خصوصی کپی می‌کند و فقط سرویس عمومی خود را دوباره بارگذاری می‌کند. نمونه‌های کامل Certbot و acme.sh در docs/HTTPS.md آمده‌اند.",
  ],
  tlsHTTPUpgrade: [
    "For an HTTP panel, add --enable-https to the first install command. This restarts only the public panel and requires signing in again; tunnels continue independently.",
    "برای پنل HTTP، در اولین دستور نصب --enable-https را اضافه کنید. فقط سرویس عمومی پنل دوباره اجرا می‌شود و باید دوباره وارد شوید؛ تونل‌ها مستقل ادامه می‌دهند.",
  ],
} satisfies Messages;
