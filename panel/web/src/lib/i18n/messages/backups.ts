// Backup, restore and migration.
import type { Messages } from "./types";

export const backups = {
  backupDownloadScope: [
    "An encrypted recovery file you keep outside this server. Open it here to inspect and verify it before you need to restore.",
    "فایل بازیابی رمزنگاری‌شده‌ای که خارج از این سرور نگه می‌دارید. می‌توانید همین‌جا آن را باز و بررسی کنید تا پیش از نیاز به بازیابی از آن مطمئن شوید.",
  ],
  backupScheduleScope: [
    "Automatic snapshots stay on this server and contain private tunnel data. Download an encrypted copy for protection against disk loss or reinstall.",
    "نسخه‌های خودکار روی همین سرور می‌مانند و داده‌های خصوصی تونل را دارند. برای خرابی دیسک یا نصب مجدد، یک کپی رمزنگاری‌شده دانلود کنید.",
  ],
  backupRestoreScope: [
    "Inspect any supported backup safely. Applying it requires an empty managed installation, and restored connections remain paused until you enable them.",
    "هر بکاپ پشتیبانی‌شده را با خیال راحت بررسی کنید. اعمال آن به تنظیمات مدیریت‌شدهٔ خالی نیاز دارد و اتصال‌ها تا فعال‌سازی شما متوقف می‌مانند.",
  ],
  backupDNSPolicies: [
    "Includes {n} domain DNS policies. The destination server keeps its own host resolver settings.",
    "شامل {n} سیاست DNS دامنه‌ها است. تنظیمات DNS خودِ سرور مقصد حفظ می‌شود.",
  ],
  backupsIntro: [
    "Keep a recovery copy. Move your setup when you need to.",
    "نسخهٔ پشتیبان بگیرید و تنظیمات را به سرور جدید منتقل کنید.",
  ],
  backupCreate: ["Create backup", "ساخت بکاپ"],
  backupRestore: ["Restore backup", "بازیابی بکاپ"],
  backupCreateHelp: [
    "Download an encrypted copy of this server’s managed setup.",
    "نسخهٔ رمزگذاری‌شدهٔ تنظیمات همین سرور را دانلود کنید.",
  ],
  backupPassword: ["Backup password", "رمز بکاپ"],
  backupConfirmPassword: ["Confirm password", "تکرار رمز"],
  backupPasswordMismatch: [
    "The passwords do not match.",
    "رمزها یکسان نیستند.",
  ],
  backupPasswordKeep: [
    "Use at least 8 characters. Keep the password separately; it cannot be recovered.",
    "حداقل 8 نویسه وارد کنید. رمز را جدا نگه دارید؛ امکان بازیابی آن وجود ندارد.",
  ],
  backupIncludeTraffic: ["Include traffic records", "همراه با سوابق مصرف"],
  backupTrafficHelp: [
    "Includes saved totals, cycles, labels and policies. Live kernel counters are not copied. Collection stays paused after restore.",
    "مجموع مصرف، دوره‌ها، نام‌ها و سقف‌های ذخیره‌شده منتقل می‌شوند. شمارندهٔ زندهٔ سیستم منتقل نمی‌شود و ثبت مصرف پس از بازیابی خاموش می‌ماند.",
  ],
  backupDownload: ["Download backup", "دانلود بکاپ"],
  backupDownloaded: [
    "Encrypted backup downloaded",
    "بکاپ رمزگذاری‌شده دانلود شد",
  ],
  backupScope: ["What’s in your backup", "محتوای بکاپ شما"],
  backupScopeConnections: [
    "Managed forwards, HAProxy, Realm, GRE and reverse tunnel settings, with their names.",
    "تنظیمات فورواردها، HAProxy، Realm، GRE و تونل‌های معکوس، همراه با نام‌ها.",
  ],
  backupScopeSecrets: [
    "Reverse tunnel tokens and Noise keys, protected by your backup password.",
    "توکن تونل‌های معکوس و کلیدهای Noise، محافظت‌شده با رمز بکاپ.",
  ],
  backupScopeTraffic: [
    "Traffic totals and history, when selected.",
    "مجموع و تاریخچهٔ مصرف، در صورت انتخاب شما.",
  ],
  backupLocalOnly: [
    "This server only. Save the file off the server.",
    "فقط همین سرور؛ فایل را خارج از سرور نگه دارید.",
  ],
  backupLimits: ["Backup scope and limits", "محدودهٔ بکاپ"],
  backupExcluded: [
    "This is a managed-configuration backup, not an OS image. It excludes panel login, sessions, Node identities and pairing journals, external certificates, binaries, host firewall policy, tuning and legacy scripts. Back up each Node separately. Re-enroll Nodes after moving the panel. Use HTTPS or a trusted SSH port forward when sending the backup password.",
    "این بکاپ تنظیمات مدیریت‌شده است، نه تصویر کامل سیستم‌عامل. حساب پنل، نشست‌ها، هویت نودها و عملیات جفت‌سازی، گواهی‌های خارجی، فایل موتورها، قوانین عمومی فایروال، تنظیمات سیستم و اسکریپت‌های قدیمی منتقل نمی‌شوند. از هر نود جدا بکاپ بگیرید و پس از انتقال پنل، نودها را دوباره متصل کنید. برای ارسال رمز بکاپ از HTTPS یا دسترسی امن از طریق SSH استفاده کنید.",
  ],
  backupRestoreHelp: [
    "Choose a backup, check its contents, then adjust addresses for this server. Restore requires an empty managed installation.",
    "بکاپ را انتخاب کنید، محتوایش را ببینید و در صورت نیاز آی‌پی‌ها را تغییر دهید. برای بازیابی، تنظیمات مدیریت‌شدهٔ سرور مقصد باید خالی باشد.",
  ],
  backupFile: ["Recovery file · up to 28 MiB", "فایل بکاپ؛ تا 28 MiB"],
  backupFileLarge: [
    "Choose a recovery file no larger than 28 MiB.",
    "فایلی انتخاب کنید که حجم آن بیشتر از 28 MiB نباشد.",
  ],
  backupInvalidFile: [
    "This file could not be read. Choose a Tunnel Manager backup.",
    "فایل خوانده نشد. بکاپ Tunnel Manager را انتخاب کنید.",
  ],
  backupInspect: ["Open backup", "باز کردن بکاپ"],
  backupSource: ["Backup source", "سرور مبدأ بکاپ"],
  backupDestination: ["Restore to", "سرور مقصد بازیابی"],
  backupPaused: [
    "Restored resources stay paused",
    "اتصال‌ها پس از بازیابی متوقف می‌مانند",
  ],
  backupMigration: ["Address & interface changes", "تغییر آی‌پی و رابط شبکه"],
  backupMappingHelp: [
    "Leave blank to keep a value. A replacement affects every matching address in the backup, including peer and destination addresses. Keep IPv4 as IPv4 and IPv6 as IPv6. Changes do not update the other server.",
    "کادر خالی یعنی حفظ مقدار قبلی. مقدار جدید جایگزین تمام موارد همان آی‌پی در بکاپ می‌شود؛ از جمله آی‌پی همتا و مقصد. خانوادهٔ IPv4 یا IPv6 را تغییر ندهید. تنظیمات سرور مقابل خودکار تغییر نمی‌کند.",
  ],
  backupKeepValue: ["Keep original", "حفظ مقدار قبلی"],
  backupContents: ["Resources", "اتصال‌های داخل بکاپ"],
  backupCertificates: [
    "Copy these external certificates to the new server before starting the affected tunnels:",
    "پیش از روشن کردن تونل‌های مربوط، این گواهی‌های خارجی را روی سرور جدید قرار دهید:",
  ],
  backupReview: ["Check changes", "بررسی تغییرات"],
  backupRestoreAction: ["Restore paused setup", "بازیابی بدون روشن کردن"],
  backupConfirmRestore: [
    "Restore on this server?",
    "بکاپ روی این سرور بازیابی شود؟",
  ],
  backupConfirmHelp: [
    "The reviewed settings will be saved locally. No imported tunnel or traffic collection will start automatically.",
    "تنظیمات بررسی‌شده روی همین سرور ذخیره می‌شوند. هیچ تونلی یا ثبت مصرفی خودکار روشن نمی‌شود.",
  ],
  backupRestored: ["Your setup is restored", "تنظیمات بازیابی شد"],
  backupNextSteps: [
    "Install any missing engines, check local IPs and interfaces, and copy external certificates. Start GRE and reverse services from their menus, enable the forwards you need, then turn traffic collection back on. Update the peer server if the public IP changed.",
    "موتورهای لازم را نصب کنید، آی‌پی و رابط شبکه را بررسی کنید و گواهی‌های خارجی را منتقل کنید. سپس سرویس‌های GRE و معکوس را از منوی خودشان روشن کنید، فورواردهای لازم را فعال کنید و ثبت مصرف را دوباره روشن کنید. اگر آی‌پی عمومی عوض شده، تنظیمات سرور مقابل را هم تغییر دهید.",
  ],
  backupChooseAnother: ["Choose another backup", "انتخاب بکاپ دیگر"],
} satisfies Messages;
