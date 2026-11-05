import test from "node:test";
import assert from "node:assert/strict";
import {
  applies,
  cleanPlan,
  newPlan,
  scopedOwners,
  templates,
  triggerSummary,
  validatePlan,
  weekOrder,
} from "../src/features/maintenance/plans.ts";
import {
  duration,
  outageSeconds,
  reportCSV,
  uptimeTone,
} from "../src/features/health/format.ts";

const t = (key) =>
  ({
    summaryDaily: "Every day at {times}",
    summaryWeekly: "{days} at {times}",
    summaryInterval: "Every {n} h",
    summaryDown: "Down for {n} min",
    summaryLatency: "Above {ms} ms for {n} min",
    summaryUptime: "After {n} days at {times}",
  })[key] ?? key;

test("every template is a valid plan once named", () => {
  for (const template of templates) {
    const plan = cleanPlan({ ...template.plan(), name: template.id });
    assert.equal(validatePlan(plan), "", template.id);
    assert.equal(plan.action, template.action);
  }
});

test("validation mirrors the broker's limits", () => {
  const base = { ...newPlan(), name: "Nightly" };
  assert.equal(validatePlan(base), "");
  assert.equal(validatePlan({ ...base, name: " " }), "planNameInvalid");
  assert.equal(
    validatePlan({ ...base, trigger: { kind: "daily", times: ["24:00"] } }),
    "planTimesInvalid",
  );
  assert.equal(
    validatePlan({ ...base, trigger: { kind: "interval", hours: 0 } }),
    "planHoursInvalid",
  );
  assert.equal(
    validatePlan({ ...base, action: "reboot", scope: ["F000001"] }),
    "planRebootScope",
  );
  assert.equal(
    validatePlan({
      ...base,
      trigger: { kind: "uptime", uptime_days: 3, times: ["04:00"] },
    }),
    "planUptimeInvalid",
  );
  assert.equal(
    validatePlan({
      ...base,
      guards: { ...base.guards, window: "05:00-05:00" },
    }),
    "planWindowInvalid",
  );
  assert.equal(
    validatePlan({ ...base, guards: { ...base.guards, max_per_day: 0 } }),
    "planMaxInvalid",
  );
});

test("cleanPlan keeps only the active trigger's fields and drops unused guards", () => {
  const plan = cleanPlan({
    ...newPlan(),
    name: "  Heal ",
    action: "restart",
    trigger: {
      kind: "health",
      condition: "down",
      minutes: 3,
      times: ["04:30"],
      hours: 6,
    },
    guards: {
      cooldown: 30,
      max_per_day: 4,
      quiet_mbps: 0,
      quiet_wait: 30,
      window: "",
      min_uptime: 30,
    },
  });
  assert.deepEqual(plan.trigger, {
    kind: "health",
    condition: "down",
    minutes: 3,
  });
  assert.deepEqual(plan.guards, { cooldown: 30, max_per_day: 4 });
  assert.equal(plan.name, "Heal");
  const reboot = cleanPlan({
    ...newPlan(),
    name: "R",
    action: "reboot",
    scope: ["F000001"],
  });
  assert.deepEqual(reboot.scope, []);
  const times = cleanPlan({
    ...newPlan(),
    name: "T",
    trigger: { kind: "daily", times: ["05:00", "01:00", "05:00"] },
  });
  assert.deepEqual(times.trigger.times, ["01:00", "05:00"]);
});

test("refresh applies only where it never disconnects", () => {
  assert.ok(applies("refresh", "nftables") && applies("refresh", "haproxy"));
  assert.ok(!applies("refresh", "realm") && !applies("refresh", "gre"));
  assert.ok(applies("restart", "gre") && applies("restart", "rathole"));
  assert.ok(!applies("reboot", "nftables"));
  const owners = [
    { id: "F000001", name: "a", engine: "nftables" },
    { id: "F000002", name: "b", engine: "realm" },
  ];
  assert.deepEqual(
    scopedOwners({ ...newPlan(), action: "refresh" }, owners).map((o) => o.id),
    ["F000001"],
  );
  assert.deepEqual(
    scopedOwners({ ...newPlan(), scope: ["F000002"] }, owners).map((o) => o.id),
    ["F000002"],
  );
});

test("trigger summaries and week order follow the locale", () => {
  const day = (d) => ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][d];
  const plan = (trigger) => ({ ...newPlan(), trigger });
  assert.equal(
    triggerSummary(plan({ kind: "daily", times: ["04:30", "16:30"] }), t, day),
    "Every day at 04:30, 16:30",
  );
  assert.equal(
    triggerSummary(
      plan({ kind: "weekly", days: [5, 6], times: ["04:30"] }),
      t,
      day,
    ),
    "Fri, Sat at 04:30",
  );
  assert.equal(
    triggerSummary(
      plan({
        kind: "health",
        condition: "latency",
        minutes: 10,
        latency_ms: 400,
      }),
      t,
      day,
    ),
    "Above 400 ms for 10 min",
  );
  assert.deepEqual(weekOrder("fa"), [6, 0, 1, 2, 3, 4, 5]);
  assert.deepEqual(weekOrder("en"), [1, 2, 3, 4, 5, 6, 0]);
});

test("health formatting uses Latin digits and status-page thresholds", () => {
  assert.equal(duration(8100, "en"), "2h 15m");
  assert.equal(duration(8100, "fa"), "2 ساعت 15 دقیقه");
  assert.equal(duration(0, "en"), "0s");
  assert.equal(uptimeTone(99.9), "ok");
  assert.equal(uptimeTone(98), "warn");
  assert.equal(uptimeTone(90), "bad");
  assert.equal(uptimeTone(null), "none");
  const from = "2026-11-01T00:00:00Z",
    to = "2026-11-08T00:00:00Z";
  assert.equal(
    outageSeconds(
      { start: "2026-10-31T23:00:00Z", end: "2026-11-01T01:00:00Z" },
      from,
      to,
    ),
    3600,
  );
  assert.equal(
    outageSeconds(
      { start: "2026-11-07T23:30:00Z" },
      from,
      to,
      Date.parse("2026-11-09T00:00:00Z"),
    ),
    1800,
  );
});

test("report CSV neutralizes formulas and keeps empty values empty", () => {
  const csv = reportCSV(
    {
      rows: [
        {
          owner: "F000001",
          name: "=cmd",
          engine: "nftables",
          checks: 1,
          uptime: 99.5,
          outages: 0,
          downtime_seconds: 0,
        },
      ],
      traffic: {},
    },
    ["Name", "ID"],
  );
  const [header, row] = csv.split("\r\n");
  assert.equal(header, '"Name","ID"');
  assert.ok(
    row.startsWith(`"'=cmd","F000001","nftables","99.5","0","0","",""`),
  );
});
