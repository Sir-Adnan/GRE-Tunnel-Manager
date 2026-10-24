import { test } from "node:test";
import assert from "node:assert/strict";
import { migrationValues, maxBackupBytes } from "../src/features/backups/contract.ts";

test("migration drops blank/unchanged fields and trims replacements", () => {
  assert.deepEqual(migrationValues({ "192.0.2.1": " 192.0.2.2 ", "::1": "", eth0: "eth0" }), { "192.0.2.1": "192.0.2.2" });
  assert.equal(maxBackupBytes, 28 * 1024 * 1024);
});
