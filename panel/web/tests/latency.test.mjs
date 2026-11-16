import test from "node:test";
import assert from "node:assert/strict";
import {
  latencyPath,
  latencyRefresh,
  latencyRows,
  latencyTick,
} from "../src/features/health/latency.ts";

const point = (t, mean, loss) => ({
  t,
  checks: mean === null && loss === null ? 0 : 4,
  mean_ms: mean,
  max_ms: mean === null ? null : mean + 10,
  jitter_ms: null,
  loss,
});

test("latency rows keep gaps and draw loss only where it happened", () => {
  const rows = latencyRows({
    owner: "gre-1",
    name: "Tunnel",
    range: "24h",
    step_seconds: 3600,
    points: [
      point("2026-11-16T10:00:00Z", 30, 0),
      point("2026-11-16T11:00:00Z", null, null),
      point("2026-11-16T12:00:00Z", 42.5, 25),
    ],
    summary: point("2026-11-16T10:00:00Z", 35, 10),
  });
  assert.deepEqual(rows[0], {
    time: Date.parse("2026-11-16T10:00:00Z"),
    mean: 30,
    max: 40,
    band: [30, 40],
    loss: null,
  });
  assert.equal(rows[1].mean, null);
  assert.equal(rows[1].band, null);
  assert.equal(rows[2].loss, 25);
});

test("latency requests, refresh and axis labels", () => {
  assert.equal(
    latencyPath("gre tun/7", "7d"),
    "health/latency?owner=gre%20tun%2F7&range=7d",
  );
  assert.equal(latencyRefresh("1h"), 60);
  assert.equal(latencyRefresh("30d"), 1800);
  const at = Date.parse("2026-11-16T09:05:00Z");
  assert.equal(latencyTick(at, "1h", "en", "UTC"), "09:05");
  assert.doesNotMatch(latencyTick(at, "30d", "fa", "UTC"), /[۰-۹]/);
  // An unknown zone falls back to the browser's.
  assert.ok(latencyTick(at, "24h", "en", "Not/AZone"));
});
