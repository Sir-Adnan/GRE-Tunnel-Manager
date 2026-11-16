// IP addresses page: server addresses, the one-screen "IP changed" fix, the
// paired address-change job and additional addresses.
import type { Messages } from "./types";

export const addresses = {
  addresses: ["IP addresses", "آی‌پی‌ها"],
  ipIntro: [
    "This server's addresses and what uses each. After the datacenter changes an IP, move every tunnel, connection and reverse tunnel to the new one in one step. Additional IPs are kept in the manager's own units.",
    "آی‌پی‌های این سرور و اینکه هر کدام کجا استفاده شده است. وقتی دیتاسنتر آی‌پی را عوض می‌کند، همه‌ی تونل‌ها، اتصال‌ها و تونل‌های معکوس را یک‌جا به آی‌پی جدید منتقل کنید. آی‌پی‌های اضافه در یونیت‌های خود برنامه نگه داشته می‌شوند.",
  ],
  ipLoadFailed: [
    "The address report could not be read.",
    "گزارش آی‌پی‌ها خوانده نشد.",
  ],
  addressGone: [
    "No longer on this server — settings still use it",
    "دیگر روی این سرور نیست؛ تنظیمات هنوز از آن استفاده می‌کنند",
  ],

  // Stale banner
  ipStaleTitle: [
    "{a} is no longer on this server",
    "آی‌پی {a} دیگر روی این سرور نیست",
  ],
  ipStaleHelp: [
    "Saved settings that still use it: {n}. They cannot work until they move to the new address.",
    "{n} تنظیم ذخیره‌شده هنوز از آن استفاده می‌کند و کار نمی‌کند. آن‌ها را به آی‌پی جدید منتقل کنید.",
  ],
  ipFixNow: ["Fix now", "اصلاح"],

  // Server addresses
  ipServerAddresses: ["Server addresses", "آی‌پی‌های سرور"],
  ipServerAddressesHelp: [
    "The main interface comes first. Container bridges are hidden.",
    "اینترفیس اصلی اول آمده است. آی‌پی‌های داکر و کانتینرها نمایش داده نمی‌شوند.",
  ],
  ipNoAddresses: ["No global addresses were found.", "آی‌پی عمومی پیدا نشد."],
  ipUplink: ["Main", "اصلی"],
  ipUplinkInterface: [
    "Main interface (default route)",
    "اینترفیس اصلی (مسیر پیش‌فرض)",
  ],
  ipExtraBadge: ["Additional", "اضافه"],
  ipTemporary: ["Temporary", "موقت"],
  ipTemporaryHelp: [
    "Added by hand and set nowhere else: the next restart removes it, and connections on it stop.",
    "دستی اضافه شده و جای دیگری تنظیم نشده است: با ری‌استارت بعدی حذف می‌شود و اتصال‌های روی آن قطع می‌شوند.",
  ],
  ipKeep: ["Keep after restart", "ماندگار کن"],
  ipKept: [
    "{ip} is kept; it comes back after every restart.",
    "{ip} ماندگار شد و بعد از هر ری‌استارت برمی‌گردد.",
  ],
  ipUnused: ["Not used by saved settings", "در تنظیمات ذخیره‌شده استفاده نشده"],
  ipUsedBy: ["Used by {n}", "استفاده در {n} مورد"],
  ipContainersHidden: [
    "Container addresses not shown: {n}.",
    "{n} آی‌پی کانتینر نمایش داده نشده است.",
  ],

  // IP changed sheet
  ipChangeTitle: ["IP changed", "آی‌پی عوض شد"],
  ipChangeIntro: [
    "Choose the old and the new address, review what changes and apply. Each item is checked and restored if it fails to start.",
    "آی‌پی قدیم و جدید را انتخاب کنید، فهرست تغییرات را ببینید و اعمال کنید. هر مورد بررسی می‌شود و اگر بالا نیاید به حالت قبل برمی‌گردد.",
  ],
  ipWhoseAddress: ["Whose IP changed?", "آی‌پی کدام سرور عوض شد؟"],
  ipThisServer: ["This server", "این سرور"],
  ipOtherServer: ["Another server", "سرور دیگر"],
  ipNoLocalUses: [
    "No saved setting uses a specific address of this server.",
    "هیچ تنظیم ذخیره‌شده‌ای از آی‌پی مشخصی از این سرور استفاده نمی‌کند.",
  ],
  ipNoRemoteUses: [
    "No saved setting points to another server's address.",
    "هیچ تنظیم ذخیره‌شده‌ای به آی‌پی سرور دیگری اشاره نمی‌کند.",
  ],
  ipOld: ["Old IP", "آی‌پی قدیم"],
  ipNew: ["New IP", "آی‌پی جدید"],
  ipGone: ["No longer on this server", "دیگر روی این سرور نیست"],
  ipSuggested: ["Main address of this server", "آی‌پی اصلی این سرور"],
  ipAddFirst: [
    "This server has no other address of this family. Add the new address first (Add IP).",
    "این سرور آی‌پی دیگری از این نوع ندارد. اول آی‌پی جدید را اضافه کنید (افزودن آی‌پی).",
  ],
  ipNoOld: ["Choose the old address.", "آی‌پی قدیم را انتخاب کنید."],
  ipBadNew: ["Enter a valid public address.", "یک آی‌پی معتبر وارد کنید."],
  ipFamilyMismatch: [
    "Both addresses must be IPv4, or both IPv6.",
    "هر دو آی‌پی باید IPv4 یا هر دو IPv6 باشند.",
  ],
  ipSameAddress: [
    "The new address is the same as the old one.",
    "آی‌پی جدید با آی‌پی قدیم یکی است.",
  ],
  ipNotOnServer: [
    "The new address is not on this server.",
    "آی‌پی جدید روی این سرور نیست.",
  ],
  ipNothingChosen: [
    "Choose at least one item.",
    "دست‌کم یک مورد را انتخاب کنید.",
  ],
  ipWhatChanges: ["What changes", "چه چیزهایی تغییر می‌کند"],
  ipCount: ["Items: {n}", "{n} مورد"],
  ipUse_gre_local: ["GRE tunnel · local end", "تونل GRE · سر این سرور"],
  ipUse_gre_remote: ["GRE tunnel · other end", "تونل GRE · سر مقابل"],
  ipUse_connection_local: [
    "Connection · listen address",
    "اتصال · آی‌پی ورودی",
  ],
  ipUse_connection_remote: ["Connection · destination", "اتصال · مقصد"],
  ipUse_reverse_local: [
    "Reverse tunnel · listen address",
    "تونل معکوس · آی‌پی ورودی",
  ],
  ipUse_reverse_remote: [
    "Reverse tunnel · server address",
    "تونل معکوس · آی‌پی سرور",
  ],
  ipAutoBoth: ["Both servers", "هر دو سرور"],
  ipRebuild: ["Recreate", "ساخت دوباره"],
  ipRebuildHelp: [
    "A WSS reverse tunnel has its own HTTPS gateway on the old address; delete it and create it again with the new one.",
    "تونل معکوس WSS یک gateway جدای HTTPS روی آی‌پی قدیم دارد؛ آن را حذف کنید و با آی‌پی جدید دوباره بسازید.",
  ],
  ipPartnerAuto: [
    "{n} holds the other end of these GRE tunnels. It moves its side in the same job, and you confirm once the tunnel works.",
    "سر دیگر این تونل‌های GRE روی {n} است. آن سرور هم در همین کار سمت خودش را عوض می‌کند و وقتی تونل کار کرد تأیید می‌کنید.",
  ],
  ipPartnerOutdated: [
    "{n} holds the other end, but its Agent is older than {v}. Update it to change both sides from here, or run the command below there.",
    "سر دیگر روی {n} است ولی نسخه‌ی Agent آن قدیمی‌تر از {v} است. برای تغییر هر دو سمت از اینجا آن را به‌روز کنید، یا دستور زیر را روی آن سرور اجرا کنید.",
  ],
  ipPartnerOffline: [
    "{n} holds the other end but is not online with operations enabled. Run the command below there.",
    "سر دیگر روی {n} است ولی آنلاین نیست یا عملیات روی آن فعال نیست. دستور زیر را روی آن سرور اجرا کنید.",
  ],
  ipPeerTitle: ["On the other server", "روی سرور مقابل"],
  ipPeerHelpLocal: [
    "These servers still send to the old address. Run this on each of them:",
    "این سرورها هنوز به آی‌پی قدیم وصل می‌شوند. این دستور را روی هر کدام اجرا کنید:",
  ],
  ipPeerHelpRemote: [
    "The server whose address changed must move its own end too. Run this there once the new address is on it:",
    "سروری که آی‌پی‌اش عوض شده باید سر خودش را هم عوض کند. وقتی آی‌پی جدید روی آن فعال شد، این دستور را آنجا اجرا کنید:",
  ],
  ipApply: ["Apply changes ({n})", "اعمال {n} تغییر"],
  ipItemDone: ["Moved", "منتقل شد"],
  ipItemFailed: ["Restored", "برگشت داده شد"],
  ipSomeFailed: [
    "Some items could not start on the new address and were restored. The others were moved.",
    "بعضی موارد روی آی‌پی جدید بالا نیامدند و به حالت قبل برگشتند. بقیه منتقل شدند.",
  ],
  ipJobFailed: [
    "The job on both servers could not start:",
    "کار مشترک دو سرور شروع نشد:",
  ],

  // Paired job
  ipJobTitle: ["GRE on both servers", "GRE روی هر دو سرور"],
  ipJobConfirmHelp: [
    "Both ends now use the new address. Check that the tunnel works, then keep it. Without confirmation both sides return to the old address.",
    "هر دو سر حالا از آی‌پی جدید استفاده می‌کنند. کار کردن تونل را بررسی کنید و بعد نگه دارید. اگر تأیید نکنید هر دو سمت به آی‌پی قدیم برمی‌گردند.",
  ],
  ipJobConfirm: ["Tunnel works — keep", "تونل کار می‌کند؛ نگه‌دار"],
  ipJobRollback: ["Return to the old address", "برگشت به آی‌پی قدیم"],
  readdressChanged: ["Changed server", "سرور تغییرکرده"],
  readdressPeer: ["Other end", "سر مقابل"],
  readdress_preparing: ["Checking both servers", "بررسی هر دو سرور"],
  readdress_applying: ["Moving tunnel ends", "در حال تغییر سرهای تونل"],
  readdress_awaiting_confirmation: ["Test and confirm", "بررسی و تأیید"],
  readdress_confirming: ["Saving confirmation", "ثبت تأیید"],
  readdress_succeeded: ["Moved on both servers", "روی هر دو سرور منتقل شد"],
  readdress_rolling_back: [
    "Returning to the old address",
    "در حال برگشت به آی‌پی قدیم",
  ],
  readdress_rolled_back: ["Returned to the old address", "به آی‌پی قدیم برگشت"],
  readdress_needs_attention: ["Inspection required", "نیاز به بررسی"],

  // Additional addresses
  ipExtraTitle: ["Additional IPs", "آی‌پی‌های اضافه"],
  ipExtraHelp: [
    "Addresses the manager adds and keeps after reboots, each in its own unit. Additional IPs are not part of backups.",
    "آی‌پی‌هایی که برنامه اضافه می‌کند و بعد از ریبوت هم می‌مانند؛ هر کدام در یونیت جدا. آی‌پی‌های اضافه در بکاپ نیستند.",
  ],
  ipExtraNone: [
    "No additional IPs are managed here.",
    "آی‌پی اضافه‌ای اینجا مدیریت نمی‌شود.",
  ],
  ipExtraAdd: ["Add IP", "افزودن آی‌پی"],
  ipExtraActive: ["Active", "فعال"],
  ipExtraStopped: ["Stopped", "متوقف"],
  ipExtraMissing: ["Not on interface", "روی اینترفیس نیست"],
  ipExtraMainRoute: [
    "Replies use the main route",
    "پاسخ‌ها از مسیر اصلی می‌روند",
  ],
  ipExtraOwnRoute: [
    "Replies use its own gateway:",
    "پاسخ‌ها از gateway خودش می‌روند:",
  ],
  ipExtraRemove: ["Remove {a}", "حذف {a}"],
  ipExtraRemoveHelp: [
    "The address and its return route are removed from the server. Move anything that uses it first.",
    "آی‌پی و مسیر برگشت آن از سرور حذف می‌شوند. اول هر چیزی را که از آن استفاده می‌کند منتقل کنید.",
  ],
  ipExtraRemoveConfirm: ["Remove", "حذف"],
  ipExtraIntro: [
    "Add an address your provider assigned to this server. It is applied now and again at every boot.",
    "آی‌پی‌ای را که ارائه‌دهنده به این سرور داده اضافه کنید. همین حالا و بعد از هر بوت اعمال می‌شود.",
  ],
  ipExtraAddress: ["Address", "آی‌پی"],
  ipExtraAddressHelp: [
    "With its prefix, as the provider gave it, for example 203.0.113.40/32. Without a prefix a single address (/32 or /128) is used.",
    "همراه با prefix، همان‌طور که ارائه‌دهنده داده است؛ مثلاً 203.0.113.40/32. بدون prefix، یک آی‌پی تکی (/32 یا /128) در نظر گرفته می‌شود.",
  ],
  ipExtraInterface: ["Interface", "اینترفیس"],
  ipExtraRoute: ["Return route", "مسیر برگشت"],
  ipExtraRouteHelp: [
    "Most providers route additional IPs through the main gateway. Choose a separate gateway only when the provider gave one for this address; a source rule then sends its replies there.",
    "بیشتر ارائه‌دهنده‌ها آی‌پی اضافه را از همان gateway اصلی عبور می‌دهند. فقط وقتی ارائه‌دهنده برای این آی‌پی gateway جدا داده، گزینه‌ی جدا را انتخاب کنید؛ در این حالت یک قانون مسیریابی پاسخ‌ها را از آن gateway می‌فرستد.",
  ],
  ipExtraRouteMain: ["Same as main", "مثل مسیر اصلی"],
  ipExtraRouteOwn: ["Separate gateway", "gateway جدا"],
  ipExtraRouteMainHelp: [
    "No extra route or rule is added.",
    "مسیر یا قانون اضافه‌ای ساخته نمی‌شود.",
  ],
  ipExtraGateway: ["Gateway of this address", "gateway این آی‌پی"],
  ipExtraGatewayHelp: [
    "From the provider's panel. It gets its own routing table and a rule for replies from this address.",
    "از پنل ارائه‌دهنده. یک جدول مسیریابی جدا و یک قانون برای پاسخ‌های این آی‌پی می‌گیرد.",
  ],
  ipExtraSubmit: ["Add and test", "افزودن و تست"],
  ipExtraBadAddress: [
    "Enter a valid address, like 203.0.113.40/32.",
    "یک آی‌پی معتبر وارد کنید؛ مثل 203.0.113.40/32.",
  ],
  ipExtraBadPrefix: [
    "Use a prefix of /8 to /32 (IPv6: /128).",
    "prefix باید بین /8 و /32 باشد (IPv6 تا /128).",
  ],
  ipExtraExists: [
    "This address is already on the server.",
    "این آی‌پی از قبل روی سرور هست.",
  ],
  ipExtraBadGateway: [
    "The gateway must be an address of the same family.",
    "gateway باید آی‌پی‌ای از همان نوع باشد.",
  ],
  ipExtraNeedGateway: [
    "Enter the gateway, or choose the main route.",
    "gateway را وارد کنید یا مسیر اصلی را انتخاب کنید.",
  ],
  ipExtraAdded: ["Address added", "آی‌پی اضافه شد"],
  ipExtraAddedHelp: [
    "The unit keeps it after reboots. Tests run on this server only.",
    "یونیت آن را بعد از ریبوت هم نگه می‌دارد. تست‌ها فقط روی همین سرور انجام شدند.",
  ],
  ipCheckPresent: [
    "The address is on the interface",
    "آی‌پی روی اینترفیس قرار گرفت",
  ],
  ipCheckRoute: [
    "Replies from it use its own gateway",
    "پاسخ‌های آن از gateway خودش می‌روند",
  ],
  ipCheckOk: ["passed", "موفق"],
  ipCheckFailed: ["failed", "ناموفق"],
  ipExtraCheckHelp: [
    "A check did not pass. Compare the address, prefix and gateway with the provider's panel; the unit stays so you can inspect it with journalctl.",
    "یکی از بررسی‌ها موفق نبود. آی‌پی، prefix و gateway را با پنل ارائه‌دهنده مقایسه کنید؛ یونیت باقی می‌ماند تا بتوانید آن را با journalctl بررسی کنید.",
  ],
} satisfies Messages;
