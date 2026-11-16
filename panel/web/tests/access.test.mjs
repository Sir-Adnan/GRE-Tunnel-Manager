import test from "node:test";
import assert from "node:assert/strict";
import { certificateSource, certificateState } from "../src/features/settings/access.ts";

test("panel-renewed short-lived certificates warn only when renewal is overdue", () => {
  const now = Date.parse("2026-11-06T12:00:00Z");
  const ip = {
    protocol: "https", self_signed: false, trusted: true, hostname_ok: true,
    not_before: "2026-11-05T12:00:00Z", not_after: "2026-11-11T12:00:00Z",
    renewal: { source: "letsencrypt", auto_renew: true },
  };
  assert.equal(certificateState(ip, now), "valid");
  assert.equal(certificateState(ip, Date.parse("2026-11-10T13:00:00Z")), "expiring");
  assert.equal(certificateState({ ...ip, renewal: undefined }, now), "expiring");
});

test("certificate source follows the renewal record, then the certificate", () => {
  const base = { protocol: "https", self_signed: false, trusted: true, hostname_ok: true };
  assert.equal(certificateSource({ ...base, protocol: "http" }), "http");
  assert.equal(certificateSource({ ...base, renewal: { source: "letsencrypt", auto_renew: true } }), "managed");
  assert.equal(certificateSource({ ...base, renewal: { source: "acme", auto_renew: false } }), "external");
  assert.equal(certificateSource({ ...base, renewal: { source: "external", auto_renew: false } }), "external");
  assert.equal(certificateSource({ ...base, self_signed: true }), "selfSigned");
  assert.equal(certificateSource(base), "external");
});

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

test("certificate addresses: public IPs and domains only", async () => {
  const { certificateHostError, httpsAddress, emailValid } = await import("../src/features/settings/access.ts");
  for (const ok of ["", "203.0.113.10", "panel.example.com", "2001:db8::10", "a-b.example.co"]) assert.equal(certificateHostError(ok), "", ok);
  for (const local of ["10.0.0.5", "192.168.1.2", "172.20.0.1", "127.0.0.1", "::1", "fd00::5", "fe80::1"]) assert.equal(certificateHostError(local), "tlsHostPrivate", local);
  for (const bad of ["-x", "panel", "a b.com", "--host=x", "panel..com"]) assert.equal(certificateHostError(bad), "tlsHostInvalid", bad);
  assert.equal(httpsAddress("Panel.Example.com", { hostname: "203.0.113.10", port: "2053" }), "https://panel.example.com:2053/");
  assert.equal(httpsAddress("", { hostname: "203.0.113.10", port: "" }), "https://203.0.113.10/");
  assert.equal(httpsAddress("2001:db8::10", { hostname: "x", port: "8443" }), "https://[2001:db8::10]:8443/");
  assert.equal(emailValid(""), true);
  assert.equal(emailValid("ops@example.com"), true);
  assert.equal(emailValid("ops@example"), false);
});
