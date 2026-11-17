import test from "node:test";
import assert from "node:assert/strict";
import { passwordIssue, passwordStrength } from "../src/features/settings/password.ts";

test("a new panel password follows the server rule before it is sent", () => {
  assert.deepEqual(passwordIssue("old-password", "short", "short"), { field: "next", key: "passwordTooShort" });
  assert.deepEqual(passwordIssue("old-password", "x".repeat(73), "x".repeat(73)), { field: "next", key: "passwordTooShort" });
  // 24 Persian letters are 48 bytes: accepted; 40 are 80 bytes: refused.
  assert.equal(passwordIssue("old", "رمز".repeat(8), "رمز".repeat(8)), undefined);
  assert.equal(passwordIssue("old", "ر".repeat(40), "ر".repeat(40))?.key, "passwordTooShort");
  assert.deepEqual(passwordIssue("old-password", "new\u0007password", "new\u0007password"), { field: "next", key: "passwordTooShort" });
  assert.deepEqual(passwordIssue("same-password", "same-password", "same-password"), { field: "next", key: "srvPasswordSame" });
  assert.deepEqual(passwordIssue("old-password", "new-password", "new-passw0rd"), { field: "repeat", key: "passwordMismatch" });
  assert.equal(passwordIssue("old-password", "new-password", "new-password"), undefined);
});

test("strength favours length", () => {
  assert.equal(passwordStrength("abcdefgh"), "weak");
  assert.equal(passwordStrength("abcdef1234"), "fair");
  assert.equal(passwordStrength("a long pass phrase"), "strong");
});
