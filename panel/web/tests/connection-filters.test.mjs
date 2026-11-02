import test from "node:test";
import assert from "node:assert/strict";
import {
  connectionStatus,
  creationEngine,
  creationEngines,
  engineCounts,
  engineFilter,
  filterConnections,
  statusFilter,
} from "../src/lib/connection-filters.ts";

const rows = [
  {
    id: "H1",
    name: "Frankfurt",
    engine: "haproxy",
    ports: "443",
    enabled: true,
    status: "active",
    targets: [{ ip: "198.51.100.20" }],
  },
  {
    id: "N1",
    name: "WireGuard",
    engine: "nftables",
    ports: "51820",
    enabled: true,
    targets: [{ ip: "198.51.100.30" }],
  },
  {
    id: "I1",
    name: "Legacy",
    engine: "iptables",
    ports: "8080",
    enabled: false,
    targets: [{ ip: "2001:db8::1" }],
  },
  {
    id: "R1",
    name: "Relay",
    engine: "realm",
    ports: "9000-9010",
    enabled: true,
    status: "failed",
    targets: [{ ip: "203.0.113.5" }],
  },
];

test("engine chips group both kernel engines and count every row once per chip", () => {
  assert.deepEqual(engineCounts(rows), {
    all: 4,
    kernel: 2,
    haproxy: 1,
    realm: 1,
  });
  assert.deepEqual(
    filterConnections(rows, { engine: "kernel" }).map((r) => r.id),
    ["N1", "I1"],
  );
});

test("status follows the live state, then the saved record", () => {
  assert.equal(connectionStatus(rows[0]), "active");
  assert.equal(connectionStatus(rows[1]), "configured");
  assert.equal(connectionStatus(rows[2]), "disabled");
  assert.deepEqual(
    filterConnections(rows, { status: "disabled" }).map((r) => r.id),
    ["I1"],
  );
});

test("search matches names, ids, ports and destinations, ignoring case and padding", () => {
  assert.deepEqual(
    filterConnections(rows, { query: "  frank " }).map((r) => r.id),
    ["H1"],
  );
  assert.deepEqual(
    filterConnections(rows, { query: "2001:DB8" }).map((r) => r.id),
    ["I1"],
  );
  assert.deepEqual(
    filterConnections(rows, { engine: "realm", query: "9000" }).map(
      (r) => r.id,
    ),
    ["R1"],
  );
});

test("URL values are allowlisted and filtered views choose sensible creation engines", () => {
  assert.equal(engineFilter("<script>"), "all");
  assert.equal(engineFilter("kernel"), "kernel");
  assert.equal(statusFilter("constructor"), "all");
  assert.equal(creationEngine("kernel"), "nftables");
  assert.equal(creationEngine("all"), "haproxy");
  assert.deepEqual(creationEngines("kernel"), ["nftables", "iptables"]);
  assert.equal(creationEngines("all"), undefined);
});
