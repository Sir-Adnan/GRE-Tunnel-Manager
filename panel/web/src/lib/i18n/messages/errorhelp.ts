// Error explanations: what happened (eh_*) and what to do (ehFix_*) for
// known engine and broker errors; see lib/error-help.ts.
import type { Messages } from "./types";

export const errorhelp = {
  ehWhat: ["What to do", "چه کار کنم"],
  ehDetails: ["Technical details", "جزئیات فنی"],
  ehUnknown: ["The operation failed", "عملیات انجام نشد"],
  ehUnknownFix: [
    "Nothing was changed by the failed step. Read the details below; if it repeats, run the connection's check or the server review under Maintenance.",
    "مرحله‌ی ناموفق چیزی را تغییر نداد. جزئیات پایین را بخوانید؛ اگر تکرار شد، بررسی اتصال یا بازبینی سرور در بخش نگهداری را اجرا کنید.",
  ],
  ehReload: ["Reload and try again", "بارگذاری دوباره"],
  ehOpen_firewall: ["Open Firewall", "باز کردن فایروال"],
  ehOpen_optimize: ["Open Server DNS", "باز کردن DNS سرور"],
  ehOpen_components: ["Open Components", "باز کردن اجزا"],
  ehOpen_maintenance: ["Open Maintenance", "باز کردن نگهداری"],

  eh_portInUse: ["This port is already in use", "این پورت در حال استفاده است"],
  ehFix_portInUse: [
    "Another connection or program on this server listens on it. Choose a different entrance port, or remove or stop what uses it first.",
    "اتصال یا برنامه‌ی دیگری روی این سرور به آن گوش می‌دهد. پورت ورودی دیگری انتخاب کنید یا اول آن را حذف یا متوقف کنید.",
  ],
  eh_legacyPort: [
    "An old installation uses this port",
    "یک نصب قدیمی از این پورت استفاده می‌کند",
  ],
  ehFix_legacyPort: [
    "A forward from an older version still holds it. Import it, or retire the old installation from Maintenance, then try again.",
    "یک فوروارد از نسخه‌ی قدیمی هنوز آن را نگه داشته است. آن را وارد کنید یا نصب قدیمی را از بخش نگهداری بازنشسته کنید و دوباره امتحان کنید.",
  ],
  eh_loop: [
    "The destination points back to this connection",
    "مقصد به همین اتصال برمی‌گردد",
  ],
  ehFix_loop: [
    "Traffic would circle on this server. Use the foreign server's address as the destination, or a different remote port.",
    "ترافیک روی همین سرور دور می‌زند. آدرس سرور خارج را به‌عنوان مقصد بدهید یا پورت مقصد دیگری انتخاب کنید.",
  ],
  eh_stale: [
    "The settings changed since you opened them",
    "تنظیمات بعد از باز کردن شما تغییر کرده‌اند",
  ],
  ehFix_stale: [
    "Someone, another tab or an automatic task saved a newer version. Reload to see it, then make your change again.",
    "کسی، تب دیگری یا یک کار خودکار نسخه‌ی جدیدتری ذخیره کرده است. بارگذاری دوباره کنید و تغییرتان را دوباره انجام دهید.",
  ],
  eh_serverDNS: [
    "The server's DNS change did not take effect",
    "تغییر DNS سرور اعمال نشد",
  ],
  ehFix_serverDNS: [
    "The previous DNS settings were kept. Open Server DNS to see which resolver manages this server and try again; the details name the cause.",
    "تنظیمات قبلی DNS حفظ شد. بخش DNS سرور را باز کنید تا ببینید کدام سرویس DNS این سرور را مدیریت می‌کند و دوباره امتحان کنید؛ علت در جزئیات آمده است.",
  ],
  eh_nameResolve: [
    "A destination name does not resolve",
    "نام مقصد به آدرس تبدیل نمی‌شود",
  ],
  ehFix_nameResolve: [
    "Check the spelling and that the name has an address of the connection's IP version, or enter the destination's IP instead.",
    "املای نام را بررسی کنید و مطمئن شوید آدرسی با نسخه‌ی IP همین اتصال دارد، یا به‌جای آن IP مقصد را وارد کنید.",
  ],
  eh_firewall: [
    "The firewall change was not completed",
    "تغییر فایروال کامل نشد",
  ],
  ehFix_firewall: [
    "The previous firewall rules were kept where possible. Open Firewall to see what blocks traffic and fix it there.",
    "تا جای ممکن قوانین قبلی فایروال حفظ شد. صفحه‌ی فایروال را باز کنید تا ببینید چه چیزی جلوی ترافیک را می‌گیرد و همان‌جا رفعش کنید.",
  ],
  eh_entranceIP: [
    "This server no longer has that IP",
    "این سرور دیگر آن IP را ندارد",
  ],
  ehFix_entranceIP: [
    "The entrance address is not assigned here (the server's IP may have changed). Set the entrance to all addresses, or pick one of the server's current IPs.",
    "آدرس ورودی روی این سرور نیست (شاید IP سرور عوض شده باشد). ورودی را روی همه‌ی آدرس‌ها بگذارید یا یکی از IPهای فعلی سرور را انتخاب کنید.",
  ],
  eh_mixedFamily: [
    "IPv4 and IPv6 destinations are mixed",
    "مقصدهای IPv4 و IPv6 با هم آمده‌اند",
  ],
  ehFix_mixedFamily: [
    "A kernel forward uses one IP version. Keep destinations of one version, or make a second connection for the other.",
    "فوروارد کرنل فقط یک نسخه‌ی IP دارد. مقصدها را از یک نسخه نگه دارید یا برای نسخه‌ی دیگر اتصال جداگانه بسازید.",
  ],
  eh_ipv6Forwarding: ["IPv6 forwarding is off", "فوروارد IPv6 خاموش است"],
  ehFix_ipv6Forwarding: [
    "Turning it on can change how this server gets its IPv6 address, so the manager does not do it. Enable IPv6 forwarding with Router Advertisements set up, or use an IPv4 destination.",
    "روشن کردن آن ممکن است نحوه‌ی گرفتن آدرس IPv6 سرور را تغییر دهد، پس برنامه این کار را انجام نمی‌دهد. فوروارد IPv6 را همراه با تنظیم Router Advertisement روشن کنید یا از مقصد IPv4 استفاده کنید.",
  ],
  eh_missingTool: [
    "A required program is not installed",
    "برنامه‌ی لازم نصب نیست",
  ],
  ehFix_missingTool: [
    "Install the engine this connection uses from Components, then save again.",
    "موتوری را که این اتصال لازم دارد از بخش اجزا نصب کنید و دوباره ذخیره کنید.",
  ],
  eh_preflight: [
    "The new configuration did not pass its check",
    "پیکربندی جدید از بررسی رد شد",
  ],
  ehFix_preflight: [
    "Nothing was changed: the running services keep their old settings. Review the values the details name, or reset advanced options to their defaults.",
    "چیزی تغییر نکرد و سرویس‌ها با تنظیمات قبلی کار می‌کنند. مقدارهایی را که در جزئیات آمده بررسی کنید یا گزینه‌های پیشرفته را به پیش‌فرض برگردانید.",
  ],
  eh_serviceStart: ["The relay service did not start", "سرویس رله اجرا نشد"],
  ehFix_serviceStart: [
    "Open the connection's menu, choose Logs and look at the last lines; a port in use or an unreadable certificate are the usual causes.",
    "منوی اتصال را باز کنید، «لاگ‌ها» را بزنید و آخرین خطوط را ببینید؛ معمولاً پورت اشغال یا گواهی غیرقابل‌خواندن علت است.",
  ],
  eh_nameTaken: ["That name is taken", "این نام قبلاً استفاده شده"],
  ehFix_nameTaken: [
    "Choose another name, or remove the item that uses it.",
    "نام دیگری انتخاب کنید یا موردی را که از آن استفاده می‌کند حذف کنید.",
  ],
  eh_mptcp: [
    "This server's kernel does not offer MPTCP",
    "کرنل این سرور MPTCP ندارد",
  ],
  ehFix_mptcp: [
    "Choose a profile without MPTCP, or enable net.mptcp.enabled on a kernel that supports it.",
    "پروفایلی بدون MPTCP انتخاب کنید یا روی کرنلی که پشتیبانی می‌کند net.mptcp.enabled را روشن کنید.",
  ],
  eh_privileges: [
    "The panel's helper lacks permission",
    "سرویس کمکی پنل دسترسی لازم را ندارد",
  ],
  ehFix_privileges: [
    "The privileged broker service must run as root. Reinstall the panel or restart gre-manager-panel-broker on the server.",
    "سرویس broker باید با دسترسی root اجرا شود. پنل را دوباره نصب کنید یا gre-manager-panel-broker را روی سرور ری‌استارت کنید.",
  ],
  eh_session: ["Your session ended", "نشست شما تمام شده است"],
  ehFix_session: [
    "Reload the page and sign in again; your saved settings are not affected.",
    "صفحه را دوباره بارگذاری کنید و دوباره وارد شوید؛ تنظیمات ذخیره‌شده تغییری نمی‌کنند.",
  ],
  eh_unreachable: [
    "The server did not answer in time",
    "سرور به‌موقع پاسخ نداد",
  ],
  ehFix_unreachable: [
    "It may still be working. Wait a moment, reload and check whether the change is there before trying again.",
    "ممکن است هنوز در حال انجام باشد. کمی صبر کنید، صفحه را دوباره بارگذاری کنید و قبل از تلاش دوباره ببینید تغییر اعمال شده یا نه.",
  ],
} satisfies Messages;
