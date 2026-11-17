// Live per-connection throughput and the Traffic overview.
import type { Messages } from "./types";

export const live = {
  liveRate: ["Live rate", "سرعت لحظه‌ای"],
  liveRateHelp: [
    "Current speed from usage collection, refreshed every 2 seconds while this page is open.",
    "سرعت فعلی از روی ثبت مصرف؛ تا وقتی این صفحه باز است هر 2 ثانیه به‌روز می‌شود.",
  ],
  copyAll: ["Copy all", "کپی همه"],
  liveThroughput: ["Live throughput", "ترافیک لحظه‌ای"],
  liveThroughputHelp: [
    "The combined speed of every connection usage collection tracks, read from its kernel counters every 2 seconds while you watch. GRE tunnels are listed but not added to it: forwards over them already count the same bytes. Nothing runs when no page is open.",
    "سرعت مجموع همهٔ اتصال‌هایی که مصرفشان ثبت می‌شود؛ تا وقتی صفحه باز است هر 2 ثانیه از شمارنده‌های کرنل خوانده می‌شود. تونل‌های GRE در فهرست هستند ولی به مجموع اضافه نمی‌شوند، چون فورواردهای روی آن‌ها همان بایت‌ها را می‌شمارند. وقتی صفحه‌ای باز نیست، چیزی اجرا نمی‌شود.",
  ],
  liveActive: ["{n} active now", "{n} اتصال فعال"],
  liveMeasuring: ["Measuring…", "در حال اندازه‌گیری…"],
  liveOffTitle: [
    "See every connection's speed and usage",
    "سرعت و مصرف هر اتصال را ببینید",
  ],
  liveOffBody: [
    "Turn on usage collection for live speed per connection, usage this cycle, quotas and a week of history. It adds owned nftables counters; traffic never passes through the panel.",
    "با روشن کردن ثبت مصرف، سرعت لحظه‌ای هر اتصال، مصرف این دوره، سقف مصرف و تاریخچهٔ یک هفته را می‌بینید. فقط شمارنده‌های اختصاصی nftables اضافه می‌شود و ترافیک از پنل عبور نمی‌کند.",
  ],
  turnOnCollection: ["Turn on usage collection", "روشن کردن ثبت مصرف"],
  busiestNow: ["Busiest now", "پرترافیک‌ترین‌ها"],
  busiestEmpty: [
    "No traffic is passing right now.",
    "الان ترافیکی عبور نمی‌کند.",
  ],
  cycleTotals: ["This cycle", "مصرف این دوره"],
  trackedCount: ["{n} connections tracked", "مصرف {n} اتصال ثبت می‌شود"],
  quotaWatch: ["Quotas", "سقف‌ها"],
  quotaWatchBody: ["{n} near or at their quota", "{n} اتصال نزدیک یا روی سقف"],
  quotaWatchClear: ["All within quota", "همه زیر سقف"],
  topUser: ["Top user", "بیشترین مصرف"],
  tunnelsSeparate: ["{n} GRE counted separately", "{n} تونل GRE جداگانه"],
  shareOfTotal: ["{p} of all usage", "{p} از کل مصرف"],
} satisfies Messages;
