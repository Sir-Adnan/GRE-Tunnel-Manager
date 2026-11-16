<div dir="rtl" align="right">

# GRE Tunnel Manager

### تونل، پورت فوروارد و رله برای سرورهایتان؛ همه از یک وب‌پنل ساده و مرتب.

[![Release](https://img.shields.io/github/v/release/Sir-Adnan/GRE-Tunnel-Manager?style=flat-square)](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/releases/latest)
[![Checks](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/actions/workflows/checks.yml/badge.svg)](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/actions/workflows/checks.yml)

**فارسی** · [English](README.md)

[نصب](#نصب-در-یک-دقیقه) · [امکانات](#چرا-gre-tunnel-manager) · [راهنماها](docs/fa/README.md) · [تغییرات](docs/CHANGELOG.md)

## نصب در یک دقیقه

روی دبیان یا اوبونتو:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh)"
```

نصب‌کننده هر مرحله را با نوار پیشرفت نشان می‌دهد، پنج سؤال کوتاه می‌پرسد (آدرس، HTTPS یا HTTP، پورت، نام کاربری و رمز، موتورها) و در پایان آدرس پنل را چاپ می‌کند. همان پورت را در فایروال باز کنید و وارد شوید.

**بدون سؤال؛ یکی از این‌ها را انتخاب کنید:**

```bash
URL=https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh

# HTTPS معتبر برای آی‌پی سرور، پورت تصادفی، رمز ساخته‌شده
sudo bash -c "$(curl -fsSL $URL)" @ --yes

# HTTP با پورت، نام کاربری و رمز دلخواه
sudo bash -c "$(curl -fsSL $URL)" @ --http --port 8080 --user admin --password 'my-long-password' --yes

# HTTPS برای دامنهٔ خودتان
sudo bash -c "$(curl -fsSL $URL)" @ --domain panel.example.com --port 2053 --yes
```

همهٔ گزینه‌ها، به‌روزرسانی و حذف: **[راهنمای نصب](docs/fa/INSTALL.md)**.

## چرا GRE Tunnel Manager

- **دو سرور با یک فرم.** آی‌پی سرور خارج و پورت‌ها را وارد کنید؛ پنل تونل GRE و فوروارد روی آن را می‌سازد و مقادیر لازم برای سمت دیگر را نشان می‌دهد.
- **همهٔ روش‌ها در یک جا.** iptables و nftables در کرنل، GRE و ip6gre، HAProxy، Realm، FRP و rathole، همه در صفحهٔ **اتصال‌ها**.
- **مشکل را زودتر از کاربر ببینید.** پایش سلامت با آپتایم و تاریخچهٔ تأخیر، **بررسی** مسیر بسته برای هر اتصال، عیب‌یابی فایروال با رفع یک‌کلیکی و هشدار در تلگرام یا webhook.
- **امن از پایه.** HTTPS معتبر با تمدید خودکار، ورود دومرحله‌ای، برگشت خودکار تغییرات پرخطر فایروال، پشتیبان رمزنگاری‌شده و به‌روزرسانی با بررسی checksum که اگر خطا بدهد به نسخهٔ قبل برمی‌گردد.
- **سبک روی سرور.** یک فایل اجرایی Go و یک موتور Bash. ترافیک در کرنل می‌ماند و توقف پنل به تونل‌ها دست نمی‌زند.
- **فارسی و انگلیسی**، راست‌به‌چپ و چپ‌به‌راست، روی دسکتاپ و موبایل.

| روش | مناسب برای |
| --- | --- |
| **iptables / nftables** | فوروارد سریع TCP و UDP در کرنل، بازهٔ پورت، تقسیم بار |
| **GRE / ip6gre** | لینک خصوصی بین دو سرور (پروتکل 47 باید باز باشد) |
| **HAProxy** | رلهٔ TCP با بررسی سلامت، جایگزینی و حفظ مقصد هر آی‌پی |
| **Realm** | رلهٔ TCP و UDP با چند مقصد |
| **FRP / rathole** | تونل معکوس وقتی مقصد نمی‌تواند اتصال ورودی بگیرد |

GRE رمزنگاری ندارد. برای وایرگارد و ترافیک UDP روشی با پشتیبانی UDP انتخاب کنید.

## بعد از نصب

```bash
sudo gtm            # وضعیت و منو: به‌روزرسانی، HTTPS، پورت، رمز، لاگ، حذف
sudo gtm update     # به‌روزرسانی امن؛ اگر خطا بدهد نسخهٔ قبلی برمی‌گردد
```

سرورهای دیگر می‌توانند به‌عنوان **Node** وصل شوند و سرور سوم لازم نیست. [نود و ایجنت ←](docs/NODES.md)

## راهنماها

**شروع:** [نصب](docs/fa/INSTALL.md) · [راهنمای کاربری](docs/fa/USER-GUIDE.md) · [رفع مشکل](docs/fa/TROUBLESHOOTING.md) · [HTTPS](docs/fa/HTTPS.md) · [فایروال](docs/fa/FIREWALL.md)
**بیشتر:** [همهٔ راهنماها](docs/fa/README.md) · [تغییرات](docs/CHANGELOG.md)

پیش از جایگزینی یک سرویس فعال، اول روی یک پورت دیگر تست کنید و پورت‌ها و پروتکل‌های لازم را از قبل باز کنید.

</div>
