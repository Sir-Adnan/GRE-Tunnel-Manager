import test from "node:test";
import assert from "node:assert/strict";
import {
  byDay,
  eventDetail,
  eventTarget,
  relative,
  unreadBadge,
} from "../src/features/notifications/catalog.ts";
import { orderChecks } from "../src/features/diagnose/order.ts";
import { farSideChecks } from "../src/features/health/farSide.ts";
import { tunnelSummary } from "../src/features/nodes/probes.ts";
import {
  compactValue,
  groupStates,
  keyTitle,
  linkKey,
  maskCPUs,
  serverFit,
} from "../src/features/optimize/catalog.ts";
import { health } from "../src/lib/i18n/messages/health.ts";
import { maintenance } from "../src/lib/i18n/messages/maintenance.ts";
import { notifications } from "../src/lib/i18n/messages/notifications.ts";
import { history } from "../src/lib/i18n/messages/history.ts";
import { tunnels } from "../src/lib/i18n/messages/tunnels.ts";

const messages = { ...health, ...maintenance, ...notifications, ...history, ...tunnels };
const t = (key) =>
  Object.hasOwn(messages, key) ? messages[key][0] : key;
const fa = (key) =>
  Object.hasOwn(messages, key) ? messages[key][1] : key;

test("events link to their page and render localized details", () => {
  assert.deepEqual(eventTarget({ kind: "down" }), { page: "health" });
  assert.equal(eventTarget({ kind: "backup-failed" }).params.tab, "schedule");
  assert.equal(eventTarget({ kind: "test" }).page, "settings");
  const up = { kind: "up", args: { seconds: "3720" }, detail: "down for 1h 2m" };
  assert.equal(eventDetail(up, t, "en"), "Down for 1h 2m");
  assert.equal(eventDetail(up, fa, "fa"), "مدت قطعی: 1 ساعت 2 دقیقه");
  assert.equal(
    eventDetail({ kind: "failover", args: { excluded: "" } }, t, "en"),
    "Every destination receives new flows again",
  );
  assert.equal(
    eventDetail({ kind: "down", args: { endpoint: "192.0.2.1:443", reason: "timeout" } }, t, "en"),
    "192.0.2.1:443 · No answer (timeout)",
  );
  assert.equal(
    eventDetail({ kind: "maintenance", args: { action: "restart", count: "2" } }, t, "en"),
    "Restart · 2 targets",
  );
  // Unknown shapes fall back to the raw detail.
  assert.equal(eventDetail({ kind: "backup-failed", detail: "disk full" }, t, "en"), "disk full");
});

test("relative times, day groups and the badge use Latin digits", () => {
  const now = Date.parse("2026-11-05T12:00:00Z");
  assert.equal(relative("2026-11-05T11:58:00Z", now, "en"), "2 minutes ago");
  assert.match(relative("2026-11-05T09:00:00Z", now, "fa"), /^3 /);
  assert.equal(relative("not a date", now, "en"), "—");
  const groups = byDay([
    { time: "2026-11-05T11:00:00Z" },
    { time: "2026-11-05T10:00:00Z" },
    { time: "2026-11-03T10:00:00Z" },
  ]);
  assert.deepEqual(groups.map((g) => g.events.length), [2, 1]);
  assert.equal(unreadBadge(7), "7");
  assert.equal(unreadBadge(140), "99+");
});

test("diagnosis lists problems first and keeps the run order otherwise", () => {
  const ordered = orderChecks([
    { key: "a", status: "ok" },
    { key: "b", status: "warn" },
    { key: "c", status: "fail" },
    { key: "d", status: "ok" },
  ]);
  assert.deepEqual(ordered.map((c) => c.key), ["c", "b", "a", "d"]);
});

test("far-side checks pair by GRE ID and this server's address", () => {
  const listing = {
    nodes: [
      { id: "local", local: true, name: "here", probes: undefined },
      {
        id: "n1",
        local: false,
        name: "Frankfurt",
        probes: {
          seen: "2026-11-05T12:00:00Z",
          report: {
            tunnels: [
              { id: "gre-tun-7", remote: "203.0.113.10", ok: false, up: true },
              { id: "gre-tun-8", remote: "198.51.100.9", ok: true, up: true },
            ],
          },
        },
      },
    ],
  };
  const checks = farSideChecks(listing, ["203.0.113.10"]);
  assert.deepEqual(Object.keys(checks), ["gre-tun-7"]);
  assert.equal(checks["gre-tun-7"].node, "Frankfurt");
  assert.equal(checks["gre-tun-7"].ok, false);
  assert.deepEqual(farSideChecks(undefined, []), {});
  assert.deepEqual(tunnelSummary(listing.nodes[1].probes.report.tunnels), { ok: 1, total: 2 });
});

test("link keys get readable names and the card group appears only with uplinks", () => {
  assert.deepEqual(linkKey("link.eth0.rps"), { link: "eth0", setting: "rps" });
  assert.equal(linkKey("link.eth0;rm.rps"), undefined);
  assert.deepEqual(keyTitle("link.ens3.txqueuelen"), { label: "optKeyTxqueuelen", link: "ens3" });
  assert.equal(maskCPUs("ff,ffffffff"), 40);
  assert.equal(compactValue("link.eth0.rps", "0"), "off");
  assert.equal(compactValue("link.eth0.rps", "f"), "4 CPU");
  const view = { keys: [], cpus: 4, links: [{ name: "eth0", rx_queues: 1 }], flows: 0 };
  assert.ok(!groupStates(view).some((g) => g.group === "nic"));
  view.keys = [{ group: "nic", key: "link.eth0.rps", current: "0", recommended: "f", note: "change" }];
  assert.ok(groupStates(view).some((g) => g.group === "nic"));
  const inventory = { connections: [], resources: [], host: { addresses: ["203.0.113.10"] } };
  assert.ok(serverFit(inventory, view).has("nic"));
  assert.ok(!serverFit(inventory, { ...view, cpus: 1 }).has("nic"));
});

test("new message modules are bilingual with Latin digits", () => {
  for (const module of [notifications, history, tunnels]) {
    for (const [key, [en, persian]] of Object.entries(module)) {
      assert.ok(en && persian, key);
      assert.doesNotMatch(persian, /[۰-۹٠-٩]/, key);
      const placeholders = (s) => [...s.matchAll(/\{[a-z]+\}/g)].map((m) => m[0]).sort();
      assert.deepEqual(placeholders(persian), placeholders(en), key);
    }
  }
});
