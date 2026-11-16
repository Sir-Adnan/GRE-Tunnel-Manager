import test from "node:test";
import assert from "node:assert/strict";
import { describeAgent, groupSecret, qrPath, sixDigits } from "../src/features/settings/sessions.ts";
import { updateOutcome } from "../src/features/settings/update.ts";
import { checklist } from "../src/features/overview/checklist.ts";

test("session names come from the User-Agent without showing it", () => {
  const chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";
  assert.deepEqual(describeAgent(chrome), { browser: "Chrome", os: "Windows" });
  assert.deepEqual(describeAgent(chrome + " Edg/130.0"), { browser: "Edge", os: "Windows" });
  assert.deepEqual(describeAgent("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1"), { browser: "Safari", os: "iOS" });
  assert.deepEqual(describeAgent("Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"), { browser: "Firefox", os: "Linux" });
  assert.deepEqual(describeAgent("Mozilla/5.0 (Linux; Android 14) Chrome/130.0 Mobile Safari/537.36"), { browser: "Chrome", os: "Android" });
  assert.deepEqual(describeAgent(""), { browser: "", os: "" });
});

test("QR modules become one path with a quiet zone", () => {
  const { size, d } = qrPath(["10", "01"]);
  assert.equal(size, 10);
  assert.equal(d, "M4 4h1v1h-1zM5 5h1v1h-1z");
  assert.equal(groupSecret("ABCDEFGHIJ"), "ABCD EFGH IJ");
  assert.equal(sixDigits(" 123456 "), true);
  assert.equal(sixDigits("12345a"), false);
});

test("an update is judged by the version the panel reports", () => {
  const pending = { from: "1.6.0", to: "1.6.1", started: 1000 };
  const view = (over) => ({ current: "1.6.0", check: { current: "1.6.0", checked: "" }, available: true, running: true, ...over });
  assert.equal(updateOutcome(pending, view({}), 2000), "running");
  assert.equal(updateOutcome(pending, view({ current: "1.6.1", running: false }), 2000), "succeeded");
  assert.equal(updateOutcome(pending, view({ running: false, run: { state: "failed", from: "1.6.0", started: "" } }), 2000), "failed");
  // A record of an earlier run never ends the wait while the unit runs.
  assert.equal(updateOutcome(pending, view({ running: true, run: { state: "failed", from: "1.6.0", started: "" } }), 2000), "running");
  assert.equal(updateOutcome(pending, undefined, 1000 + 21 * 60 * 1000), "failed");
});

test("the getting-started checklist reflects loaded sources only", () => {
  const now = Date.parse("2026-11-16T12:00:00Z");
  const items = checklist({ connections: 0 }, now);
  assert.deepEqual(items.map((i) => i.id), ["connection"]);
  const all = checklist({
    access: { protocol: "https", self_signed: false, trusted: true, hostname_ok: true, not_before: "2026-11-01T00:00:00Z", not_after: "2027-01-30T00:00:00Z" },
    security: { two_factor: false },
    connections: 3,
    health: { settings: { enabled: true } },
    snapshots: { settings: { enabled: false } },
    notify: { settings: { webhook: { enabled: false }, telegram: { enabled: true } } },
  }, now);
  assert.deepEqual(all.map((i) => [i.id, i.done]), [["https", true], ["twoFactor", false], ["connection", true], ["health", true], ["backups", false], ["alerts", true]]);
  assert.deepEqual(all[1].params, { tab: "security" });
  const http = checklist({ access: { protocol: "http", self_signed: false, trusted: false, hostname_ok: false }, connections: 1 }, now);
  assert.equal(http[0].done, false);
});

test("a finished run that left the version unchanged is a failure", () => {
  const pending = { from: "1.6.0", to: "1.6.1", started: 1000 };
  const view = { current: "1.6.0", check: { current: "1.6.0", checked: "" }, available: true, running: false, run: { state: "succeeded", from: "1.6.0", to: "1.6.0", started: "" } };
  assert.equal(updateOutcome(pending, view, 2000), "failed");
});
