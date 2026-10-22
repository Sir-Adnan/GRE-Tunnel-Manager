import test from "node:test";
import assert from "node:assert/strict";
import { recordSamples } from "../src/features/traffic/history.ts";
import { number, uptime } from "../src/lib/format.ts";

const sample = (updated, received = 100, sent = 20) => ({ updated, received, sent, source: "nftables" });
const view = (counters) => ({ counters });

test("chart does not fabricate points for missing, duplicate or older samples", () => {
  const empty = recordSamples({}, view({ A: sample("0001-01-01T00:00:00Z") }));
  assert.deepEqual(empty, {});
  const first = recordSamples({}, view({ A: sample("2026-10-22T10:00:00Z") }));
  const duplicate = recordSamples(first, view({ A: sample("2026-10-22T10:00:00Z", 150) }));
  const older = recordSamples(duplicate, view({ A: sample("2026-10-22T09:00:00Z") }));
  assert.equal(older.A.length, 1);
  assert.equal(older.A[0].received, 100);
});

test("overlapping GRE and forward resources remain separate", () => {
  const result = recordSamples({}, view({ GRE: sample("2026-10-22T10:00:00Z", 1200), FORWARD: sample("2026-10-22T10:00:00Z", 1000) }));
  assert.deepEqual(Object.keys(result).sort(), ["FORWARD", "GRE"]);
  assert.equal(result.GRE[0].received, 1200);
  assert.equal(result.FORWARD[0].received, 1000);
});

test("long visits retain at most 60 samples and discard removed resources", () => {
  let history = {};
  for (let index = 0; index < 100; index++) history = recordSamples(history, view({ A: sample(new Date(Date.UTC(2026, 9, 22, 10, index)).toISOString(), index) }));
  assert.equal(history.A.length, 60);
  assert.equal(history.A[0].received, 40);
  assert.deepEqual(recordSamples(history, view({})), {});
});

test("display numbers localize without changing technical input values", () => {
  assert.equal(number(123, "fa"), "۱۲۳");
  assert.equal(number(123, "en"), "123");
  assert.equal(uptime("4h15m0s", "fa"), "۴ ساعت · ۱۵ دقیقه");
  assert.equal(uptime("4h15m0s", "en"), "4 h · 15 m");
});
