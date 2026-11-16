// Connection check: the live packet path, the check after saving and the
// source-address and firewall badges on connection cards.
import type { Messages } from "./types";

export const check = {
  chkTab: ["Check", "بررسی"],
  chkSaved: [
    "Saved and applied. Here is how the connection is doing.",
    "ذخیره و اعمال شد. وضعیت اتصال را اینجا می‌بینید.",
  ],
  chkChecks: ["Checks on this server", "بررسی‌های روی این سرور"],
  chkChecksHelp: [
    "Reads the rules, services and settings this connection needs, then tries to reach each destination from this server.",
    "قوانین، سرویس‌ها و تنظیماتی را که این اتصال لازم دارد می‌خواند و از همین سرور به هر مقصد وصل می‌شود.",
  ],

  // Packet path
  pathTitle: ["Live packet path", "مسیر زنده‌ی بسته‌ها"],
  pathHelp: [
    "Where this connection's traffic goes right now, read from the manager's own rule counters (kernel forwards) or open connections (relays). Nothing is sent to test it.",
    "ترافیک این اتصال همین حالا کجا می‌رود. از شمارنده‌ی قوانین خود برنامه (اتصال‌های کرنل) یا اتصال‌های باز (رله‌ها) خوانده می‌شود و هیچ بسته‌ی آزمایشی ارسال نمی‌شود.",
  ],
  pathLoadFailed: [
    "The packet path could not be read.",
    "مسیر بسته‌ها خوانده نشد.",
  ],
  pathClients: ["Clients", "کاربران"],
  pathFirewall: ["Firewall", "فایروال"],
  pathDestination: ["Destination", "مقصد"],
  pathNewRate: ["{n} new/s", "{n} اتصال جدید در ثانیه"],
  pathNewTotal: ["{n} connections", "{n} اتصال"],
  pathConnected: ["{n} connected now", "{n} اتصال باز"],
  pathOpen: ["{n} open", "{n} اتصال باز"],
  pathBlockedRate: ["{n} blocked/s", "{n} مسدود در ثانیه"],
  pathBlockedTotal: ["{n} blocked", "{n} مسدود"],
  pathNoBlocks: ["Nothing blocked", "چیزی مسدود نشده"],
  pathDropsHere: [
    "{tool} drops these packets",
    "{tool} این بسته‌ها را رد می‌کند",
  ],
  pathForward: ["Forwards in the kernel", "عبور در کرنل"],
  pathRelay: ["Relays with {engine}", "رله با {engine}"],
  pathSourceServer: [
    "Destination sees this server's IP",
    "مقصد IP این سرور را می‌بیند",
  ],
  pathSourceClient: [
    "Destination sees the client's IP",
    "مقصد IP کاربر را می‌بیند",
  ],
  pathSent: ["Sent", "ارسال"],
  pathReceived: ["Received", "دریافت"],
  pathPackets: ["{n} pkt/s", "{n} بسته/ثانیه"],
  pathLive: [
    "Updates every {n} s; rates cover the last interval.",
    "هر {n} ثانیه به‌روز می‌شود؛ نرخ‌ها مربوط به آخرین بازه هستند.",
  ],
  pathTotals: [
    "Totals since the rules were last applied; rates appear with the next update.",
    "مجموع از آخرین اعمال قوانین؛ نرخ‌ها با به‌روزرسانی بعدی نمایش داده می‌شوند.",
  ],
  pathStopsHere: ["Traffic stops here", "ترافیک اینجا متوقف می‌شود"],

  // Verdicts
  pathVerdict_disabled: [
    "This connection is disabled",
    "این اتصال غیرفعال است",
  ],
  pathVerdictBody_disabled: [
    "It is saved but has no rules or service, so it carries no traffic. Enable it to use it.",
    "ذخیره شده اما قانون یا سرویسی ندارد، پس ترافیکی از آن عبور نمی‌کند. برای استفاده، فعالش کنید.",
  ],
  pathVerdict_dropped: [
    "This server's firewall drops the traffic",
    "فایروال این سرور ترافیک را رد می‌کند",
  ],
  pathVerdictBody_dropped: [
    "{tool} keeps a FORWARD DROP policy (UFW or Docker) and the manager's accept rule is missing there. Fix it to let this connection through.",
    "{tool} سیاست FORWARD DROP دارد (UFW یا Docker) و قانون اجازه‌ی برنامه آنجا نیست. با «رفع» اجازه‌ی عبور این اتصال را بدهید.",
  ],
  pathVerdict_idle: ["Waiting for traffic", "در انتظار ترافیک"],
  pathVerdictBody_idle: [
    "No client is using this connection right now. Connect from a client (for example, turn on your VPN app) and watch the path move.",
    "الان کاربری از این اتصال استفاده نمی‌کند. از یک کاربر وصل شوید (مثلاً برنامه‌ی VPN را روشن کنید) و تغییر مسیر را ببینید.",
  ],
  pathVerdict_stuck: [
    "Traffic arrives but does not leave this server",
    "ترافیک می‌رسد اما از این سرور خارج نمی‌شود",
  ],
  pathVerdictBody_stuck: [
    "Clients reach this server, yet nothing goes on to a destination. Another firewall or a disabled IP forwarding stops it; the checks below show which.",
    "کاربران به این سرور می‌رسند اما چیزی به مقصد نمی‌رود. یک فایروال دیگر یا خاموش بودن IP forwarding جلوی آن را می‌گیرد؛ بررسی‌های پایین علت را نشان می‌دهند.",
  ],
  pathVerdict_noAnswer: [
    "The destination does not answer",
    "مقصد پاسخ نمی‌دهد",
  ],
  pathVerdictBody_noAnswer: [
    "Traffic leaves this server but no reply comes back. Check that the service runs on the destination port and that the destination's firewall allows this server's IP.",
    "ترافیک از این سرور خارج می‌شود اما پاسخی برنمی‌گردد. بررسی کنید سرویس روی پورت مقصد در حال اجرا باشد و فایروال مقصد به IP این سرور اجازه بدهد.",
  ],
  pathVerdictBody_noAnswerRelay: [
    "Clients are connected, but the relay has no connection to any destination. Check that the destination is up and allows this server's IP.",
    "کاربران وصل هستند اما رله به هیچ مقصدی وصل نیست. بررسی کنید مقصد روشن باشد و به IP این سرور اجازه بدهد.",
  ],
  pathVerdict_partial: [
    "Some destinations do not answer",
    "بعضی مقصدها پاسخ نمی‌دهند",
  ],
  pathVerdictBody_partial: [
    "No reply comes back from {list}. Clients sent there may fail; check those servers or remove them.",
    "از {list} پاسخی برنمی‌گردد. کاربرانی که به آن‌ها فرستاده می‌شوند ممکن است وصل نشوند؛ آن سرورها را بررسی یا حذف کنید.",
  ],
  pathVerdict_flowing: [
    "Traffic flows both ways",
    "ترافیک در هر دو جهت جریان دارد",
  ],
  pathVerdictBody_flowing: [
    "Clients reach this server, it forwards them and the destination answers.",
    "کاربران به این سرور می‌رسند، ترافیک به مقصد می‌رود و مقصد پاسخ می‌دهد.",
  ],
  pathFixNow: ["Fix now", "رفع"],
  pathOpenFirewall: ["Open Firewall", "باز کردن فایروال"],

  // Badges on connection cards
  cbSourceServer: ["Server IP", "IP سرور"],
  cbSourceClient: ["Client IP", "IP کاربر"],
  cbSourceHelp: [
    "The address the destination sees: this server's IP (masquerade) or the client's own IP.",
    "آدرسی که مقصد می‌بیند: IP این سرور (masquerade) یا IP خود کاربر.",
  ],
  cbAllow: ["Allow list", "فقط مجازها"],
  cbDeny: ["Block list", "مسدودها"],
  cbLimited: ["Limited", "محدود"],
  cbUFWClosed: ["Closed in UFW", "بسته در UFW"],
  cbForwardBlocked: ["Forward blocked", "عبور مسدود"],
  cbFirewallHelp: [
    "Open the Firewall page for this connection.",
    "صفحه‌ی فایروال این اتصال را باز کنید.",
  ],
  // Status chip and route chain in the connection list.
  route: ["Route", "مسیر"],
  toneOk: [
    "Running; nothing known blocks it",
    "در حال کار؛ مانعی دیده نمی‌شود",
  ],
  toneWarn: ["Needs a look", "نیاز به بررسی"],
  toneProblem: ["Stopped or blocked", "متوقف یا مسدود"],
  toneOff: ["Turned off", "خاموش"],
  tonePending: ["Changing or not known yet", "در حال تغییر یا هنوز نامشخص"],
} satisfies Messages;
