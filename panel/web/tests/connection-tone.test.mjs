import test from "node:test";
import assert from "node:assert/strict";
import { connectionTone } from "../src/lib/connection-tone.ts";

const on = (status) => ({ status, enabled: true });

test("running relays and loaded kernel rules are ok", () => {
  assert.equal(connectionTone(on("active")), "ok");
  assert.equal(connectionTone(on("configured"), "up"), "ok");
  assert.equal(connectionTone(on("active"), "off"), "ok");
});

test("disabled connections are off whatever else is known", () => {
  assert.equal(
    connectionTone({ status: "failed", enabled: false }, "down"),
    "off",
  );
  assert.equal(connectionTone({ status: "disabled", enabled: true }), "off");
});

test("a stopped service, failed checks or a blocking firewall are problems", () => {
  assert.equal(connectionTone(on("failed")), "problem");
  assert.equal(connectionTone(on("inactive")), "problem");
  assert.equal(connectionTone(on("active"), "down"), "problem");
  assert.equal(
    connectionTone(on("configured"), "up", [{ tone: "problem" }]),
    "problem",
  );
});

test("degraded checks and closed UFW ports are warnings", () => {
  assert.equal(connectionTone(on("active"), "degraded"), "warn");
  assert.equal(
    connectionTone(on("active"), "up", [{}, { tone: "warn" }]),
    "warn",
  );
});

test("transitions and unknown states are pending, never ok", () => {
  assert.equal(connectionTone(on("activating")), "pending");
  assert.equal(connectionTone(on("unknown")), "pending");
  assert.equal(connectionTone(on(undefined)), "pending");
});
