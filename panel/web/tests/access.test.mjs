import test from "node:test";
import assert from "node:assert/strict";
import { certificateState } from "../src/features/settings/access.ts";

test("certificate status separates encryption, client trust and expiry", () => {
  const now = Date.parse("2026-11-06T12:00:00Z");
  const certificate = { protocol: "https", not_after: "2026-12-06T12:00:00Z", self_signed: false, trusted: true, hostname_ok: true };
  assert.equal(certificateState({ ...certificate, protocol: "http" }, now), "http");
  assert.equal(certificateState(certificate, now), "valid");
  assert.equal(certificateState({ ...certificate, self_signed: true, trusted: false }, now), "selfSigned");
  assert.equal(certificateState({ ...certificate, trusted: false }, now), "privateCA");
  assert.equal(certificateState({ ...certificate, not_after: "2026-11-07T12:00:00Z" }, now), "expiring");
  assert.equal(certificateState({ ...certificate, not_after: "2026-11-05T12:00:00Z" }, now), "expired");
  assert.equal(certificateState({ ...certificate, not_after: "invalid" }, now), "expired");
});
