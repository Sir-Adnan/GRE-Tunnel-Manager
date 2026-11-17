import test from "node:test";
import assert from "node:assert/strict";
import { filterOwners, healthCounts } from "../src/features/health/filter.ts";

const owner = (name, status, address = "") => ({
  owner: name.toUpperCase(),
  name,
  status,
  targets: address ? [{ address }] : [],
});
const rows = [
  owner("nl", "up", "10.0.1.1"),
  owner("de", "degraded"),
  owner("fi", "up"),
  owner("tr", "down"),
  owner("fr", "unknown"),
];

test("health rows put problems first and filter by state and text", () => {
  assert.deepEqual(filterOwners(rows, "all").map((o) => o.name), ["tr", "de", "fr", "fi", "nl"]);
  assert.deepEqual(filterOwners(rows, "problems").map((o) => o.name), ["tr", "de"]);
  assert.deepEqual(filterOwners(rows, "up").map((o) => o.name), ["fi", "nl"]);
  assert.deepEqual(filterOwners(rows, "all", "10.0.1").map((o) => o.name), ["nl"]);
  assert.deepEqual(filterOwners(rows, "all", " DE ").map((o) => o.name), ["de"]);
  assert.deepEqual(healthCounts(rows), { all: 5, problems: 2, up: 2 });
});
