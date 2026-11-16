import test from "node:test";
import assert from "node:assert/strict";
import { pushSample, sparkPath, sparkSamples } from "../src/lib/sparkline.ts";

test("history keeps the newest samples and skips missing readings", () => {
  let h = [];
  for (let i = 0; i < sparkSamples + 5; i++) h = pushSample(h, i);
  assert.equal(h.length, sparkSamples);
  assert.equal(h[0], 5);
  assert.equal(pushSample(h, null), h);
  assert.equal(pushSample(h, Number.NaN), h);
});

test("a path needs two points and ends at the right edge", () => {
  assert.equal(sparkPath([], 58, 20), "");
  assert.equal(sparkPath([3], 58, 20), "");
  const path = sparkPath([0, 50, 100], 58, 20, 100);
  assert.match(path, /^M54\.0 19\.0 L56\.0 10\.0 L58\.0 1\.0$/);
});

test("without a fixed maximum the largest value leaves headroom; all zeros stay flat", () => {
  assert.equal(sparkPath([1, 2], 58, 20), "M56.0 11.5 L58.0 4.0");
  assert.equal(sparkPath([0, 0], 58, 20), "M56.0 19.0 L58.0 19.0");
});
