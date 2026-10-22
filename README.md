<div align="center">

# GRE Tunnel Manager

### تونل، فوروارد پورت و لودبالانس؛ ساده و در دسترس

مدیریت تونل و فوروارد روی سرورهای لینوکس، با Bash ماژولار و بدون پنل وب.

[![Release](https://img.shields.io/badge/release-v1.2.1-0891b2?style=flat-square)](docs/CHANGELOG.md)
[![Checks](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/actions/workflows/checks.yml/badge.svg)](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/actions/workflows/checks.yml)
![Platform](https://img.shields.io/badge/Linux-Debian%20%2F%20Ubuntu-334155?style=flat-square)
![Runtime](https://img.shields.io/badge/runtime-Bash-334155?style=flat-square)

[شروع سریع](#شروع-سریع) · [راهنمای استفاده](docs/USER-GUIDE.md) · [تنظیمات ظاهر](docs/TERMINAL-UI.md) · [تاریخچه](docs/CHANGELOG.md)

</div>

---

## شروع سریع

**نیازمندی‌ها:** سرور Debian یا Ubuntu با systemd، دسترسی SSH، ابزار `curl` و دسترسی root یا `sudo`.

در ترمینال سرور، این **دستور تک‌خطی** را وارد کنید:

```bash
curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/gre.sh -o gre.sh && sudo bash gre.sh
```

فایل `gre.sh` در پوشهٔ فعلی ذخیره و منوی برنامه باز می‌شود. نصب اجزای موردنیاز هنگام انتخاب روش مربوط انجام می‌شود. برای اجرای دوباره، در همان پوشه `sudo bash gre.sh` را بزنید.

<details>
<summary>با root وارد شده‌ام، یا curl نصب نیست</summary>

اگر با کاربر **root** وارد شده‌اید، از این دستور استفاده کنید؛ `sudo` لازم نیست:

```bash
curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/gre.sh -o gre.sh && bash gre.sh
```

اگر خطای `curl: command not found` دیدید، ابتدا نصبش کنید و دستور بالا را دوباره بزنید:

```bash
sudo apt-get update && sudo apt-get install -y curl
```

برای کاربر root، `sudo` را از فرمان نصب هم حذف کنید. دریافت دوباره، فایل `gre.sh` پوشهٔ فعلی را با نسخهٔ مخزن جایگزین می‌کند.

</details>

## از کجا شروع کنم؟

1. بخش موردنیاز را انتخاب کنید؛ مثلاً **GRE Tunnel** یا **Port Forwarding**.
2. IP سرورها، پورت ورودی و مقصد را طبق راهنمای منو وارد کنید.
3. خلاصهٔ تنظیمات را بخوانید و تغییرات را تأیید کنید.

| می‌خواهم… | بخش مناسب |
| --- | --- |
| تونل GRE بسازم | **1: GRE Tunnel**؛ سپس Kharej Server یا Iran Server |
| یک پورت را مستقیم یا روی GRE فوروارد کنم | **2: Port Forwarding** |
| تونل HAProxy یا Realm بسازم | **3: HAProxy Tunnel** یا **4: Realm Tunnel** |
| تونل معکوس بسازم | **5: Reverse Tunnel**؛ FRP یا rathole |
| بین چند سرور لودبالانس کنم | **6: Load Balancing** |

نمایش، ویرایش و حذف، داخل همان بخش هستند؛ مثلاً برای حذف HAProxy وارد **HAProxy Tunnel → Delete tunnel** شوید.

برای فوروارد مستقیم نیازی به ساخت GRE ندارید. سرویس مقصد باید از قبل فعال باشد؛ این برنامه کانفیگ یا کلیدهای VPN را نمی‌سازد.

## چه امکاناتی دارد؟

- **GRE / ip6gre:** ارتباط شبکه بین سرورها با مدیریت لینک و MTU.
- **iptables / nftables:** فوروارد TCP و UDP در کرنل، بدون سرویس دائمیِ مدیر.
- **HAProxy / Realm:** انتقال ترافیک و چند مقصد؛ HAProxy برای TCP همراه با بررسی اتصال مقصد و failover.
- **FRP / rathole:** ارتباط معکوس؛ FRP با TCP، WS، WSS و QUIC، و rathole با Noise روی TCP.
- **مدیریت اتصال‌ها:** شناسهٔ مستقل، ویرایش، فعال/غیرفعال‌سازی، حذف گروهی و نقاط بازیابی فورواردها.
- **ظاهر قابل‌انتخاب:** Dark، Light و Plain، چهار رنگ اصلی، چیدمان Guided و Compact، راهنمای English، Finglish و فارسی.

## ظاهر ترمینال

رابط برنامه داخل **همان ترمینال SSH** باز می‌شود؛ مرورگر یا پنل وب لازم ندارد. در **Settings & Tools → Appearance & language** تم، رنگ و زبان راهنما را انتخاب کنید. برای خوانایی فارسی، ابتدا **Test Farsi display** را ببینید.

```bash
sudo bash gre.sh --theme dark --layout guided --language finglish
```

اگر رنگ یا کادرها درست دیده نمی‌شوند، [راهنمای نمایش و تنظیمات ترمینال](docs/TERMINAL-UI.md) را ببینید. پیش‌نمایش بدون تغییر شبکه: `bash gre.sh --preview home`.

## چند نکتهٔ مهم

- پورت‌ها و پروتکل موردنیاز را در فایروال سرور و ارائه‌دهنده مجاز کنید. GRE رمزنگاری ندارد و باید در شبکهٔ ارائه‌دهنده پشتیبانی شود.
- برای WireGuard و AmneziaWG مسیر **UDP** انتخاب کنید؛ HAProxy این پروژه فقط TCP را منتقل می‌کند.
- پیش از جابه‌جایی سرویس اصلی، اتصال را روی یک پورت جدا آزمایش کنید. انتخاب روش و ظرفیت به مسیر و منابع سرورها بستگی دارد.

## راهنماهای بیشتر

[راهنمای استفاده](docs/USER-GUIDE.md) · [HAProxy](docs/HAPROXY.md) · [عیب‌یابی و بازیابی](docs/OPERATIONS.md) · [پاک‌سازی Legacy و تنظیمات سراسری](docs/TUNING-CLEANUP.md)

برای توسعه‌دهندگان: [معماری و مستندات](docs/README.md) · [مشارکت و تست](docs/DEVELOPMENT.md) · [AGENTS.md](AGENTS.md)

نسخهٔ قدیمی v13.9 و راهنمای آن در [legacy](legacy/README.md) نگهداری می‌شود.
