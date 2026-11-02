// Traffic usage, quotas and accounting.
import type { Messages } from "./types";

export const traffic = {
  autoPause: ["Pause traffic at quota", "توقف ترافیک پس از رسیدن به سقف"],
  autoPauseHelp: [
    "At the next successful traffic sample, block both directions for this port or GRE interface using owned nftables rules, including established flows. Services stay configured. Sampling and reconciliation can be delayed, so usage may exceed the quota. Reset usage, raise the quota or turn this option off to resume. Do not use this on your only management route.",
    "در نمونه‌برداری موفق بعدی، ترافیک هر دو جهت این پورت یا رابط GRE با قانون اختصاصی nftables متوقف می‌شود؛ اتصال‌های باز هم مسدود می‌شوند. تنظیمات سرویس باقی می‌ماند. ممکن است نمونه‌برداری یا اعمال قانون تأخیر داشته باشد و مصرف از سقف بیشتر شود. برای ادامه، مصرف را صفر کنید، سقف را افزایش دهید یا این گزینه را خاموش کنید. این گزینه را برای تنها مسیر مدیریت سرور روشن نکنید.",
  ],
  autoPauseNeedsCollection: [
    "Enable traffic collection for this resource first.",
    "ابتدا ثبت مصرف این اتصال را روشن کنید.",
  ],
  autoPauseNeedsLimit: [
    "Enter a quota greater than zero first.",
    "ابتدا سقفی بیشتر از صفر وارد کنید.",
  ],
  quotaPaused: ["Traffic paused", "ترافیک متوقف شده"],
  viewUsage: ["View usage details", "مشاهدهٔ جزئیات مصرف"],
  usageActions: ["Usage actions", "عملیات مصرف"],
  usageListHelp: [
    "Current-cycle usage for each managed connection. Missing samples are shown as unavailable, not zero. GRE and forwarded traffic can overlap; totals are not summed.",
    "مصرف دورهٔ فعلی هر اتصال؛ نبود گزارش با خط تیره نشان داده می‌شود، نه مصرف صفر. مصرف GRE و فوروارد ممکن است هم‌پوشانی داشته باشد و با هم جمع نمی‌شود.",
  ],
  allUsage: ["All connections", "فهرست مصرف‌ها"],
  quotaDialogHelp: [
    "Label this connection and set an optional cycle quota.",
    "برای این اتصال برچسب و سقف دلخواه دوره را تعیین کنید.",
  ],
  ledgerDescription: [
    "Independent usage cycles, customer labels and optional quota pauses. Network byte counters, not an invoice.",
    "دوره‌های مستقل مصرف، برچسب مشتری و توقف اختیاری در سقف مصرف. این آمار بایت‌های شبکه است، نه صورتحساب دقیق.",
  ],
  exportCSV: ["Export CSV", "خروجی CSV"],
  localAccounting: [
    "Accounting on this server. GRE and port counters can overlap; totals are never combined.",
    "آمار این سرور. شمارندهٔ GRE و پورت ممکن است هم‌پوشانی داشته باشند؛ با هم جمع نمی‌شوند.",
  ],
  usageSearch: ["Name, port or customer…", "نام، پورت یا مشتری…"],
  allMethods: ["All methods", "همهٔ روش‌ها"],
  unassignedCustomer: ["No customer label", "بدون برچسب مشتری"],
  cycleQuota: ["Cycle quota", "سقف دورهٔ مصرف"],
  quotaHelp: [
    "Set a customer label and optional GiB quota. Zero means no limit. The quota applies to the current cycle and selected direction.",
    "برچسب مشتری و سقف دلخواه بر حسب GiB را تعیین کنید. صفر یعنی بدون سقف. سقف بر اساس جهت انتخاب‌شده و دورهٔ فعلی محاسبه می‌شود.",
  ],
  quotaReached: ["Quota reached", "سقف مصرف رسیده"],
  noQuota: ["No quota", "بدون سقف"],
  advisoryQuota: [
    "Alert only. Turn on ‘Pause traffic at quota’ in Customer & quota if you want automatic blocking.",
    "فقط هشدار می‌دهد. برای توقف خودکار، در بخش مشتری و سقف مصرف، گزینهٔ توقف ترافیک را روشن کنید.",
  ],
  cycleStarted: ["Cycle started", "شروع دوره"],
  customerQuota: ["Customer & quota", "مشتری و سقف مصرف"],
  resetUsage: ["Reset usage", "صفر کردن مصرف"],
  forgetAccounting: ["Forget archived usage", "حذف آمار بایگانی‌شده"],
  resetUsageHelp: [
    "Archive the current cycle and show zero for the new cycle. Lifetime totals and the tunnel stay intact. This cannot be undone.",
    "دورهٔ فعلی بایگانی و مصرف دورهٔ جدید صفر می‌شود. مصرف کل و تونل حفظ می‌شوند. این عمل قابل بازگشت نیست.",
  ],
  disableQuotaHelp: [
    "Disable this forward using its current saved revision. Active relay connections may close; kernel connections can remain until conntrack expiry. No host conntrack flush is performed.",
    "این فوروارد با نسخهٔ فعلی تنظیمات غیرفعال می‌شود. اتصال‌های فعال رله ممکن است قطع شوند؛ اتصال‌های کرنل تا انقضای وضعیت شبکه ممکن است باقی بمانند.",
  ],
  forgetAccountingHelp: [
    "Permanently remove the accounting, customer label and cycle history of this deleted connection.",
    "آمار، برچسب مشتری و تاریخچهٔ دوره‌های این اتصال حذف‌شده برای همیشه پاک می‌شود.",
  ],
  retainedChartHelp: [
    "Actual persisted samples of this cycle. Limited by retention time and the latest 288 samples; gaps are not estimates.",
    "نمونه‌های واقعی و ذخیره‌شدهٔ این دوره. محدود به زمان نگهداری و آخرین 288 نمونه؛ فاصله‌های خالی تخمین زده نمی‌شوند.",
  ],
  historyOffHelp: [
    "History is off. Enable retention above to keep chart samples across visits and restarts.",
    "تاریخچه خاموش است. برای نگهداری نمودار پس از خروج یا راه‌اندازی مجدد، نگهداری تاریخچه را فعال کنید.",
  ],
  retainedSamples: ["retained samples", "نمونهٔ ذخیره‌شده"],
  previousCycles: [
    "Previous cycles · latest 12",
    "دوره‌های قبلی · 12 مورد آخر",
  ],
  customerLabel: ["Customer / reference", "مشتری / شناسهٔ دلخواه"],
  quotaGiB: ["Quota in GiB · 0 = unlimited", "سقف بر حسب GiB · صفر = نامحدود"],
  quotaDirection: ["Count toward quota", "جهت محاسبهٔ سقف"],

  trackedResources: ["Connections to track", "انتخاب اتصال‌ها برای ثبت مصرف"],
  trackedResource: ["Connection", "اتصال"],
  noTrackableResources: [
    "No supported connections yet.",
    "هنوز اتصال پشتیبانی‌شده‌ای وجود ندارد.",
  ],
  usageByConnection: ["Usage by connection", "مصرف هر اتصال"],
  counterSource: ["Measurement method", "روش اندازه‌گیری"],
  nftAccounting: ["nftables network counters", "شمارنده‌های شبکهٔ nftables"],
  removedResource: ["Previous connection", "اتصال قبلی"],
  trafficTrend: ["Connection usage trend", "روند مصرف اتصال"],
  chartWaitingHelp: [
    "Enable collection and refresh after a later sample. Each connection is charted separately; leaving this page clears the chart session.",
    "ثبت را روشن کنید و پس از نمونهٔ بعدی به‌روزرسانی کنید. هر اتصال نمودار جدا دارد؛ با خروج از این صفحه، نمونه‌های نمودار پاک می‌شوند.",
  ],
  autoPauseCollectionGuard: [
    "Some connections have automatic quota pauses. Keep them selected with collection enabled, or turn off their pause option in Customer & quota before saving these changes.",
    "برای بعضی اتصال‌ها توقف خودکار فعال است. ثبت مصرف و انتخاب آن‌ها را روشن نگه دارید؛ یا قبل از ذخیرهٔ این تغییرات، گزینهٔ توقف خودکارشان را از بخش مشتری و سقف مصرف خاموش کنید.",
  ],
  usageDetails: ["Details & history", "جزئیات و تاریخچه"],
  trafficSections: ["Traffic sections", "بخش‌های مصرف ترافیک"],
  retention: ["History retention", "نگهداری تاریخچه"],
  historyOff: ["Off · minimum storage", "خاموش · کمترین فضای ذخیره"],
  historyDay: ["24 hours · up to 288 samples", "24 ساعت · حداکثر 288 نمونه"],
  historyWeek: ["7 days · up to 288 samples", "7 روز · حداکثر 288 نمونه"],
  historyMonth: ["30 days · up to 288 samples", "30 روز · حداکثر 288 نمونه"],
  collectionSettings: ["Traffic collection", "تنظیمات ثبت مصرف"],
  collectionSummary: [
    "Choose what to track, then save your changes.",
    "موارد دلخواه را انتخاب کنید و تغییرات را ذخیره کنید.",
  ],
  collectionOnDraft: [
    "Enabled in this form. Save to apply.",
    "در فرم روشن است؛ برای اعمال، ذخیره کنید.",
  ],
  collectionOffDraft: [
    "Disabled in this form. Save to apply.",
    "در فرم خاموش است؛ برای اعمال، ذخیره کنید.",
  ],
  intervalHelp: [
    "15–3600 seconds. Longer intervals reduce collection work; default: 60 seconds.",
    "بین 15 تا 3600 ثانیه؛ فاصلهٔ بیشتر، نمونه‌برداری کمتری دارد. پیش‌فرض 60 ثانیه است.",
  ],
  selectResourceFirst: [
    "Select at least one connection, or enable tracking all connections.",
    "حداقل یک اتصال انتخاب کنید یا ثبت همهٔ اتصال‌ها را روشن کنید.",
  ],
  unsavedChanges: ["Unsaved changes", "تغییرات هنوز ذخیره نشده‌اند"],
  settingsApplied: [
    "Showing saved settings",
    "تنظیمات ذخیره‌شده نمایش داده می‌شوند",
  ],
  trafficDesc: [
    "Optional network counters, with control over collection cost.",
    "شمارنده‌های اختیاری شبکه، با امکان کنترل مصرف منابع.",
  ],
  collect: ["Collect traffic usage", "ثبت مصرف ترافیک"],
  collectHelp: [
    "Off by default. Enabling adds owned nftables counters and periodic samples.",
    "پیش‌فرض خاموش است؛ فعال‌سازی، شمارنده‌های اختصاصی nftables و نمونه‌برداری دوره‌ای را اضافه می‌کند.",
  ],
  interval: ["Sampling interval (seconds)", "فاصلهٔ نمونه‌برداری؛ ثانیه"],
  trackAll: [
    "Track all supported connections",
    "ثبت همهٔ اتصال‌های پشتیبانی‌شده",
  ],
} satisfies Messages;
