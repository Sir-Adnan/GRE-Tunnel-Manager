// GRE and reverse tunnel resources.
import type { Messages } from "./types";

export const resources = {
  transportHelp: [
    "TCP is a simple starting point. WS carries the connection over WebSocket; WSS adds a certificate-backed TLS gateway. QUIC and KCP need a working UDP path; KCP may use more bandwidth and is not always faster. KCP is available for local FRP setup; paired Nodes keep their existing TCP/WS/QUIC contract.",
    "حالت TCP شروع ساده‌ای است. حالت WS اتصال را روی WebSocket منتقل می‌کند و WSS یک ورودی TLS با گواهی اضافه می‌کند. برای QUIC و KCP مسیر UDP لازم است؛ KCP ممکن است پهنای باند بیشتری مصرف کند و همیشه سریع‌تر نیست. فعلاً KCP در ساخت محلی FRP در دسترس است؛ اتصال هماهنگ نودها همچنان TCP، WS و QUIC را پشتیبانی می‌کند.",
  ],
  startAtBoot: [
    "Start & enable at boot",
    "روشن کردن و اجرای خودکار پس از راه‌اندازی",
  ],
  renameDisplay: ["Display name", "نام نمایشی"],
  add: ["Add tunnel", "ساخت تونل"],
  stop: ["Stop", "توقف"],
  restart: ["Restart", "راه‌اندازی مجدد"],
  both: ["TCP + UDP", "هر دو؛ TCP و UDP"],
  tunnelID: ["Tunnel ID", "شناسهٔ تونل"],
  role: ["Server role", "نقش سرور"],
  peerIP: ["Other server IP", "آی‌پی سرور دیگر"],
  mtu: ["MTU", "اندازهٔ MTU"],
  greHelp: [
    "Use the same ID on both servers and opposite roles. GRE needs IP protocol 47 and does not encrypt traffic. No watchdog is added by this form.",
    "روی دو سرور شناسهٔ یکسان و نقش مخالف انتخاب کنید. GRE به پروتکل 47 نیاز دارد و ترافیک را رمزگذاری نمی‌کند. این فرم سرویس نگهبان اضافه نمی‌کند.",
  ],
  destinationRole: ["Destination (service server)", "مقصد؛ سرور سرویس"],
  publicPort: ["Public service port", "پورت عمومی سرویس"],
  controlPort: ["Tunnel control port", "پورت کنترل تونل"],
  host: ["Entrance server IP", "آی‌پی سرور ورودی"],
  localIP: ["Service IP", "آی‌پی سرویس"],
  localPort: ["Service port", "پورت سرویس"],
  token: ["Shared token", "توکن مشترک"],
  generate: ["Generate", "ساخت خودکار"],
  mux: ["Stream multiplexing", "چندگانه‌سازی جریان"],
  noiseKey: ["Entrance Noise public key", "کلید عمومی Noise سرور ورودی"],
  certificate: ["Local certificate / CA path", "مسیر محلی گواهی یا CA"],
  internalPort: ["Internal WSS port", "پورت داخلی WSS"],
  reverseHelp: [
    "Configure each server separately. For rathole, copy the generated entrance public key to the destination. WSS requires certificates already present on the server.",
    "هر سرور را جدا تنظیم کنید. برای rathole کلید عمومی ساخته‌شده در ورودی را به مقصد منتقل کنید. برای WSS فایل گواهی باید از قبل روی سرور موجود باشد.",
  ],
  renameHelp: [
    "Optional, up to 40 ASCII characters. Does not change the service ID, peer settings or tunnel addresses. Leave empty to restore the technical name.",
    "نام دلخواه تا 40 نویسهٔ انگلیسی. شناسهٔ سرویس، تنظیمات طرف مقابل و آدرس تونل تغییر نمی‌کنند. برای بازگشت به نام فنی خالی بگذارید.",
  ],

  greDesc: [
    "Connect two servers, then forward traffic over the link if needed.",
    "دو سرور را متصل کنید و در صورت نیاز ترافیک را از لینک عبور دهید.",
  ],
  reverseDesc: [
    "Set up both ends with matching names, ports and shared credentials.",
    "هر دو سمت را با نام، پورت‌ها و اطلاعات مشترک هماهنگ تنظیم کنید.",
  ],
} satisfies Messages;
