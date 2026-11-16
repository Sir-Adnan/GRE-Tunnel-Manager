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
  tlsManagedHelp: [
    "Trusted by browsers. The panel renews this Let's Encrypt certificate automatically.",
    "مرورگرها به این گواهی اعتماد دارند. پنل این گواهی Let's Encrypt را خودکار تمدید می‌کند.",
  ],
  tlsStaging: ["Staging", "آزمایشی"],
  tlsRenewal: ["Renewal", "تمدید"],
  tlsRenewal_managed: ["Automatic, from", "خودکار، از"],
  tlsRenewal_external: ["By your ACME client", "با ابزار ACME شما"],
  tlsRenewal_selfSigned: ["None (self-signed)", "ندارد (خودامضا)"],
  tlsRenewalFailed: [
    "The last renewal attempt failed; the current certificate stays loaded and the panel retries every six hours.",
    "آخرین تلاش برای تمدید ناموفق بود؛ گواهی فعلی بارگذاری‌شده می‌ماند و پنل هر شش ساعت دوباره تلاش می‌کند.",
  ],
  tlsTrustedGuide: [
    "Port 80 closed? Cloudflare DNS, Certbot or acme.sh",
    "پورت 80 بسته است؟ Cloudflare DNS، Certbot یا acme.sh",
  ],
  tlsIssueHelp: [
    "For a domain on Cloudflare, run this on the server through SSH and choose Cloudflare DNS. The API token stays on the server and never passes through the panel.",
    "برای دامنه‌ای که روی Cloudflare است، این دستور را از طریق SSH روی سرور اجرا کنید و Cloudflare DNS را انتخاب کنید. توکن API روی سرور می‌ماند و هرگز از پنل عبور نمی‌کند.",
  ],
  tlsIssueDetails: [
    "DNS validation needs no open port. IP certificates last six days and renew every few days; domain certificates renew about a month before they expire.",
    "اعتبارسنجی DNS به پورت باز نیازی ندارد. گواهی آی‌پی شش روز اعتبار دارد و هر چند روز تمدید می‌شود؛ گواهی دامنه حدود یک ماه پیش از پایان اعتبار تمدید می‌شود.",
  ],
  tlsGetTrusted: ["Get trusted certificate", "گرفتن گواهی معتبر"],
  tlsNewCertificate: ["Request new certificate", "درخواست گواهی جدید"],
  tlsRenewNow: ["Renew now", "تمدید همین حالا"],
  tlsRenewed: ["Certificate renewed.", "گواهی تمدید شد."],
  tlsUseSelfSigned: ["Switch to self-signed", "تغییر به گواهی خودامضا"],
  tlsIssueTitle: [
    "Trusted certificate from Let's Encrypt",
    "گواهی معتبر از Let's Encrypt",
  ],
  tlsIssueIntro: [
    "Free, trusted by browsers and renewed automatically by the panel.",
    "رایگان، مورد اعتماد مرورگرها و با تمدید خودکار توسط پنل.",
  ],
  tlsIssueHost: ["Domain or public IP", "دامنه یا آی‌پی عمومی"],
  tlsIssueHostHelp: [
    "A domain must already point to this server (DNS A or AAAA record). An IP certificate needs no domain.",
    "دامنه باید از قبل به این سرور اشاره کند (رکورد A یا AAAA). گواهی آی‌پی به دامنه نیازی ندارد.",
  ],
  tlsIssueEmail: ["Email (optional)", "ایمیل (اختیاری)"],
  tlsIssueEmailHelp: [
    "Contact address for the Let's Encrypt account.",
    "آدرس تماس برای حساب Let's Encrypt.",
  ],
  tlsIssueStaging: [
    "Test with the staging CA (browsers do not trust it)",
    "آزمایش با سرور staging (مرورگرها به آن اعتماد ندارند)",
  ],
  tlsIssuePort80: [
    "Let's Encrypt connects to TCP port 80 on this server for a few seconds. Allow it in the server and provider firewall.",
    "Let's Encrypt برای چند ثانیه به پورت TCP 80 این سرور وصل می‌شود. آن را در فایروال سرور و ارائه‌دهنده باز کنید.",
  ],
  tlsIssueSwitch: [
    "This panel uses HTTP; it restarts on HTTPS and you sign in again at",
    "این پنل از HTTP استفاده می‌کند؛ با HTTPS دوباره اجرا می‌شود و باید دوباره وارد شوید در",
  ],
  tlsIssueAction: ["Get certificate", "گرفتن گواهی"],
  tlsIssueWorking: ["Requesting…", "در حال درخواست…"],
  tlsIssued: ["Trusted certificate installed.", "گواهی معتبر نصب شد."],
  tlsHostPrivate: [
    "Use a public address; private and local addresses cannot be certified.",
    "از آدرس عمومی استفاده کنید؛ برای آدرس خصوصی یا محلی گواهی صادر نمی‌شود.",
  ],
  tlsHostInvalid: [
    "Enter a domain like panel.example.com or an IP address.",
    "دامنه‌ای مثل panel.example.com یا یک آدرس آی‌پی وارد کنید.",
  ],
  tlsEmailInvalid: [
    "Enter a valid email address or leave it empty.",
    "یک ایمیل معتبر وارد کنید یا خالی بگذارید.",
  ],
  tlsSelfSignedTitle: [
    "Switch to a self-signed certificate?",
    "به گواهی خودامضا تغییر کند؟",
  ],
  tlsSelfSignedBody: [
    "Traffic stays encrypted, but browsers warn until you trust the certificate, and automatic renewal stops. Use this when a trusted certificate cannot be renewed.",
    "ترافیک رمزنگاری‌شده می‌ماند، اما مرورگرها تا وقتی به گواهی اعتماد نکنید هشدار می‌دهند و تمدید خودکار متوقف می‌شود. وقتی گواهی معتبر قابل تمدید نیست از این گزینه استفاده کنید.",
  ],
  tlsSelfSignedDone: [
    "Self-signed certificate installed.",
    "گواهی خودامضا نصب شد.",
  ],
  tlsSwitchingTitle: ["Switching to HTTPS", "در حال انتقال به HTTPS"],
  tlsSwitchingBody: [
    "The panel restarted with its new certificate. Opening the new address in {seconds} s; sign in again there.",
    "پنل با گواهی جدید دوباره اجرا شد. آدرس جدید تا {seconds} ثانیهٔ دیگر باز می‌شود؛ آنجا دوباره وارد شوید.",
  ],
  tlsSwitchingOpen: ["Open now", "همین حالا باز کن"],
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
  tlsRenewalGuide: [
    "Or connect Certbot or acme.sh",
    "یا اتصال Certbot یا acme.sh",
  ],
  tlsRenewalHelp: [
    "For other DNS providers, issue the certificate with your ACME client first. Replace the example domain, then run this on the server. Built-in renewal turns off.",
    "برای سایر ارائه‌دهندگان DNS، ابتدا گواهی را با ابزار ACME بگیرید. دامنهٔ نمونه را عوض کنید و این دستور را روی سرور اجرا کنید. تمدید داخلی پنل خاموش می‌شود.",
  ],
  tlsRenewalHook: [
    "Use the same install command in the client's deploy hook after each successful renewal. The panel copies one private bundle and reloads only its public service. See docs/HTTPS.md for complete Certbot and acme.sh examples.",
    "همین دستور نصب را در deploy hook ابزار قرار دهید تا پس از هر تمدید موفق اجرا شود. پنل یک فایل خصوصی کپی می‌کند و فقط سرویس عمومی خود را دوباره بارگذاری می‌کند. نمونه‌های کامل Certbot و acme.sh در docs/HTTPS.md آمده‌اند.",
  ],
} satisfies Messages;
