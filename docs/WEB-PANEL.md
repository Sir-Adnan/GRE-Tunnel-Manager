# وب‌پنل GRE Tunnel Manager

پنل اختیاری Go برای مدیریت اتصال‌های همین سرور است. رابط فارسی راست‌چین و انگلیسی چپ‌چین، موبایل و دسکتاپ، تم اصلی Nettinx و تم Neutral را پشتیبانی می‌کند. ترافیک از پنل عبور نمی‌کند و توقف پنل، تونل‌ها را متوقف نمی‌کند.

## نصب و ورود

فرمان نصب مستقیم روی سرور Debian/Ubuntu با systemd:

```bash
curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/panel-install.sh -o panel-install.sh && sudo bash panel-install.sh
```

گزینهٔ **Web Panel** در منوی اصلی اسکریپت نیز همین نصب‌کننده را اجرا می‌کند. نصب‌کننده بستهٔ نسخه‌دار و checksum آن را از GitHub Releases می‌گیرد؛ بسته شامل فایل اجرایی Go، رابط ساخته‌شده و نسخهٔ هماهنگ هستهٔ Bash است. سرور به Node.js، Go، Docker یا دیتابیس نیاز ندارد.

مراحل نصب:

1. آدرس عمومی سرور را برای گواهی HTTPS وارد کنید.
2. آدرس شنود را انتخاب کنید؛ مقدار پیش‌فرض `0.0.0.0` برای همهٔ آدرس‌های IPv4 است. برای IPv6 می‌توانید `::` انتخاب کنید.
3. پورت دلخواه وارد کنید؛ ورودی خالی، پورت آزاد تصادفی انتخاب می‌کند و همان پورت ذخیره می‌شود. انتخاب تصادفی جایگزین احراز هویت نیست.
4. نام کاربری و رمز ۱۲ تا ۷۲ بایتی تعیین کنید؛ رمز روی صفحه نمایش داده نمی‌شود.
5. پورت TCP انتخابی را در فایروال سرور و ارائه‌دهنده باز کنید و آدرس `https://SERVER_IP:PORT` را باز کنید.

گواهی اولیه خودامضاست. مرورگر آن را خودکار معتبر نمی‌داند؛ اثرانگشت SHA-256 چاپ‌شده در SSH را پیش از اعتماد بررسی کنید. برای گواهی معتبر از CA، مسیرهای `certificate` و `private_key` را در فایل تنظیمات تغییر دهید؛ کلید فقط برای `root:grepanel` خواندنی بماند و سرویس پنل را restart کنید. پنل ACME یا تمدید خودکار گواهی ندارد. رمز روی HTTP عمومی ارسال نمی‌شود.

دستورهای مدیریت:

```bash
sudo gtm-panel address
sudo systemctl status gre-manager-panel --no-pager
sudo gtm-panel reset-password
sudo systemctl restart gre-manager-panel
sudo systemctl stop gre-manager-panel gre-manager-panel-broker
sudo systemctl start gre-manager-panel
```

بازنشانی رمز باید با restart پنل همراه باشد تا نشست‌های قبلی باطل شوند. تغییر پورت با ویرایش محلی `listen` در `/etc/gre-manager-panel/config.json` و restart پنل انجام می‌شود. نصب مجدد تنظیمات موجود، پورت، رمز و گواهی را حفظ می‌کند. پنل به‌صورت سرویس هنگام بوت فعال می‌شود؛ توقف موقت با غیرفعال‌کردن اجرای هنگام بوت تفاوت دارد.

## قابلیت‌های موجود

| بخش | قابلیت |
| --- | --- |
| مدیریت فوروارد | ساخت چندپورت، ویرایش تک‌پورت، انتخاب گروهی، فعال/غیرفعال و حذف با بررسی پیش از اعمال |
| پشتیبانی iptables و nftables | ورودی IPv4/IPv6، پروتکل TCP/UDP/هر دو، DNAT، تغییر پورت مقصد، masquerade یا حفظ مبدأ، انتخاب رابط و توزیع وزنی |
| مدیریت HAProxy | حالت TCP، وزن مقصدها، round robin، leastconn، source، failover، ۱۳ تنظیم محدودشدهٔ timeout/queue/maxconn/health check/slow start/PROXY/log و پریست‌های متعادل، VPN و کم‌مصرف |
| مدیریت Realm | حالت TCP/UDP/هر دو، چند مقصد با وزن، round robin و iphash، تنظیم timeout، keepalive، تعداد probe، هدرهای PROXY ورودی/خروجی و سطح لاگ |
| مدیریت GRE | ساخت GRE/ip6gre با شناسه، نقش، آدرس محلی/مقابل و MTU؛ وضعیت، start/stop/restart، لاگ و حذف با کنترل وابستگی‌ها |
| مدیریت FRP | ورودی/مقصد، پروتکل TCP یا UDP، انتقال TCP/WS/WSS/QUIC، stream multiplexing و گروه لودبالانس TCP |
| مدیریت rathole | ورودی/مقصد، سرویس TCP/UDP/هر دو، Noise NK، ساخت کلید در ورودی و pin کلید عمومی در مقصد |
| مدیریت موتورهای تونل | نصب انتخابی یا یکجای موتورهای اختیاری، بدون ساخت تونل |

مرز پشتیبانی مشخص است: پنل ویرایشگر همهٔ قابلیت‌های بومی HAProxy، Realm یا تمام قوانین فایروال لینوکس نیست. ویرایش دلخواه متن config، HAProxy HTTP/ACL/TLS routing، انتقال رمزگذاری‌شدهٔ بومی Realm، MPTCP، hostname مقصد، مدیریت هم‌زمان چند سرور و ویرایش فایل دلخواه از طریق وب ارائه نمی‌شوند. بخش قابلیت‌ها در API و فرم‌ها مبنای پشتیبانی است. انتقال‌های رمزگذاری‌شدهٔ فعلی از FRP و rathole ارائه می‌شوند.

پریست‌ها مقدار اولیهٔ تنظیمات را انتخاب می‌کنند؛ عملکرد یا مصرف یکسان روی همهٔ شبکه‌ها تضمین نمی‌کنند. هدر PROXY فقط وقتی روشن شود که برنامهٔ همسایه آن را انتظار داشته باشد. حفظ آی‌پی مبدأ به مسیر برگشت صحیح نیاز دارد. وضعیت «تنظیم‌شده» برای فوروارد کرنل، گواه دسترس‌پذیری مقصد نیست و سرویس فعال نیز اتصال صحیح همتا را اثبات نمی‌کند.

پیکربندی طرف دیگر GRE و Reverse روی همان سرور دیگر انجام می‌شود. فرم GRE وب، watchdog یا تغییرات سراسری فایروال/sysctl ایجاد نمی‌کند؛ پروتکل ۴۷ و سیاست‌های عبور ترافیک باید در شبکه مجاز باشند. شناسه و نقش‌های آن با قرارداد keyed فعلی سازگارند. تنظیمات GRE و Reverse خارج از restore point فورواردها باقی می‌مانند.

## آمار اختیاری

ثبت آمار پیش‌فرض خاموش است. با روشن‌کردن، جدول اختصاصی `inet gtm_panel_metrics` فقط شمارنده اضافه می‌کند؛ هیچ ruleset سراسری پاک نمی‌شود و verdict عبور/مسدودسازی اضافه نمی‌شود. برای آمار فوروارد، حتی وقتی موتور iptables است، نصب nftables لازم است. خاموش‌کردن ثبت، جدول اختصاصی را حذف و نمونه‌برداری را متوقف می‌کند؛ مجموع‌های ذخیره‌شده باقی می‌مانند.

شیوهٔ شمارش:

- شمارنده‌های فوروارد کرنل، مسیر forward و جهت اصلی/برگشت conntrack را اندازه می‌گیرند؛ شمارندهٔ زنجیرهٔ NAT معیار حجم کل نیست.
- شمارنده‌های HAProxy و Realm، سمت ورودی کاربر را در input/output اندازه می‌گیرند و اتصال دوم رله به مقصد دوباره جمع زده نمی‌شود.
- شمارنده‌های Reverse، پورت عمومی سمت ورودی را اندازه می‌گیرند؛ حجم هر سرویس در کانال چندگانهٔ سمت مقصد از روی حجم کانال کنترل حدس زده نمی‌شود.
- شمارنده‌های GRE از rx/tx رابط خوانده می‌شوند. همان بسته ممکن است در آمار GRE و فوروارد دیده شود؛ این مجموع‌ها به هم اضافه نمی‌شوند.

حجم‌ها شامل بایت‌های لایهٔ شبکه‌اند، نه حجم خالص برنامه یا صورتحساب دیتاسنتر. جهت دریافت/ارسال به سمت ورودی یا رابط اندازه‌گیری‌شده اشاره دارد. نشست‌های NOTRACK، offloadهایی که مسیر شمارش را دور می‌زنند، DNAT به خود میزبان و مسیرهای سفارشی می‌توانند خارج از پوشش شمارندهٔ forward باشند. بازهٔ نمونه‌برداری ۱۵ تا ۳۶۰۰ ثانیه و پیش‌فرض ۶۰ ثانیه است؛ همهٔ موارد یا موارد انتخابی قابل ثبت‌اند.

مجموع‌ها و آخرین نمونه به‌صورت دوره‌ای ذخیره می‌شوند و کاهش شمارنده، reset تشخیص داده می‌شود. توقف ناگهانی یا حذف شمارنده پیش از نمونهٔ بعدی ممکن است بخشی از حجم را از دست بدهد؛ ثبت صورتحساب دقیق ادعا نمی‌شود. هنگام توقف پنل با آمار روشن، شمارنده‌های کرنل باقی می‌مانند؛ برای حذف هزینهٔ شمارش، ابتدا ثبت را خاموش کنید.

## معماری و توسعه

سرویس عمومی با کاربر محدود `grepanel` و HTTPS اجرا می‌شود؛ عملیات شبکه از طریق Unix socket با دسترسی گروهی به broker محلی می‌روند. درخواست‌ها ساختار مشخص دارند، فرمان دلخواه اجرا نمی‌شود، ورودی‌ها هم در Go و هم Bash بررسی می‌شوند و shell interpolation/eval استفاده نمی‌شود. عملیات فوروارد از قفل، state کامل، پیش‌بررسی، snapshot و بازیابی موجود استفاده می‌کند. revision هر ردیف جلوی بازنویسی و حذف انتخاب‌های قدیمی را می‌گیرد.

نشست‌ها در حافظه و با عمر چهار ساعت‌اند؛ cookie دارای HttpOnly، Secure و SameSite است. تغییرها به بررسی Origin و CSRF نیاز دارند. ورود محدود می‌شود، اندازهٔ ورودی و خروجی و تعداد عملیات محدود است. پسورد با bcrypt ذخیره می‌شود؛ پیش‌فرض قابل ورود برای نصب واقعی وجود ندارد. محیط demo فقط روی loopback اجرا می‌شود و به فرمان‌های سیستم دسترسی ندارد.

ساختار کد:

| مسیر | مسئولیت |
| --- | --- |
| پوشهٔ `panel/internal/model` | قراردادها، قابلیت‌ها، تبدیل و اعتبارسنجی state |
| پوشهٔ `panel/internal/control` | broker، آداپتر Bash، موجودی و آمار |
| پوشهٔ `panel/internal/auth` | ورود، نشست و CSRF |
| پوشهٔ `panel/internal/httpapi` | HTTP و عملیات پس‌زمینهٔ محدود |
| پوشهٔ `panel/web/src/features` | صفحه‌ها و فرم‌ها، مستقل از تم |
| پوشهٔ `panel/web/src/experience` | قرارداد ظاهر، تم‌ها، انتخاب و جهت زبان |
| ماژول‌های `src/api.sh` و `src/links.sh` و `src/reverse_api.sh` | عملیات غیرتعاملی اعتبارسنجی‌شده |

ظاهر دقیق Nettinx با درخواست کاربر حفظ شده است. نسبت کنتراست متن سفید دکمهٔ اصلی حدود ۲٫۵:۱ در روشن و ۲٫۶۲:۱ در تیره است و برخی رنگ‌های منوی کناری نیز AA را تأمین نمی‌کنند. این محدودیت ثبت شده و به‌عنوان عبور از آزمون کنتراست گزارش نمی‌شود. تم Neutral برای انتخاب جداگانه وجود دارد. فونت‌ها محلی‌اند؛ حروف فارسی tracking ندارند و IP/پورت/لاگ مستقل چپ‌به‌راست‌اند.

## English reference

The optional panel serves an embedded React/shadcn frontend from a prebuilt Go binary. Install with the command above, choose a port (blank selects a free random port), and create administrator credentials. Open **HTTPS**, allow the chosen TCP port, and verify the self-signed certificate fingerprint through SSH. You can replace the certificate/key paths with trusted certificate files; automatic ACME renewal is not included.

The restricted public service delegates allowlisted operations to a private root broker over a group-protected Unix socket. The existing Bash manager remains the state and reconciliation authority. Tunnel traffic never crosses the panel. Existing TSV v1/v2 remain compatible; Realm advanced options use v3. Older releases cannot load v3: use a suitable older snapshot before downgrade.

The capability table above lists the supported adapters. This is not a full native configuration editor. HAProxy HTTP/TLS/ACL routing, native Realm encrypted transports, arbitrary firewall rules, and multi-server orchestration remain separate future work. GRE and reverse peers are configured independently on each host.

Metrics are off by default. Enable nftables accounting for managed entrance ports and interface counters for GRE; choose all or selected resources and a 15–3600 second sample interval. Counters measure network bytes, not application payload or billable traffic. NAT chains are not used as full-flow byte counters. GRE and forwarded traffic may overlap. Totals are checkpointed; abrupt resets can lose uncollected increments. Disable collection to remove its separate nftables table and periodic sampling.

The original user-selected Nettinx colors are preserved, including known contrast failures. Locale/direction, appearance, engine capabilities and security remain independent. The terminal keeps its fixed English interface.
