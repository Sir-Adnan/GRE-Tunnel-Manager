import test from "node:test";
import assert from "node:assert/strict";
import {
  duplicatePorts,
  isHostname,
  mappingSamples,
  parseSpans,
  portIn,
  remoteSpans,
  targetPorts,
  totalPorts,
} from "../src/lib/ports.ts";
import { applyOrder, mergeOrder } from "../src/lib/order-list.ts";
import { filterConnections } from "../src/lib/connection-filters.ts";

test("kernel ranges stay one span; relays expand to single ports", () => {
  const kernel = parseSpans("443, 2000-2999,8443", true);
  assert.deepEqual(kernel.spans, [
    { first: 443, last: 443 },
    { first: 2000, last: 2999 },
    { first: 8443, last: 8443 },
  ]);
  assert.equal(totalPorts(kernel.spans), 1002);
  assert.equal(parseSpans("8000-8002", false).spans.length, 3);
  assert.equal(parseSpans("8000-8040", false).error, "relayRange");
  assert.equal(parseSpans("2000-2999,2500", true).error, "overlap");
  assert.equal(parseSpans("1-4097", true).error, "invalid");
  assert.equal(parseSpans("2000-1999", true).error, "invalid");
  assert.equal(parseSpans("", true).error, "empty");
  assert.equal(parseSpans(Array.from({ length: 33 }, (_, i) => i + 1).join(","), true).error, "tooMany");
});

test("port mapping: same, one port and mapped ranges", () => {
  const local = parseSpans("2000-2999,8443", true).spans;
  assert.deepEqual(remoteSpans(local, "same", "", 0).spans, local);
  assert.deepEqual(remoteSpans(local, "", "", 443).spans, [
    { first: 443, last: 443 },
    { first: 443, last: 443 },
  ]);
  const mapped = remoteSpans(local, "map", "3000-3999, 443", 0);
  assert.equal(mapped.error, undefined);
  assert.deepEqual(mappingSamples(local, mapped.spans), [
    { from: "2000-2999", to: "3000-3999" },
    { from: "8443", to: "443" },
  ]);
  assert.equal(remoteSpans(local, "map", "3000-3999", 0).error, "mapCount");
  assert.equal(remoteSpans(local, "map", "3000-3500,443", 0).error, "mapSize");
  // A single remote port takes a whole range.
  assert.equal(remoteSpans(local, "map", "443,443", 0).error, undefined);
});

test("domains, port lists and duplicate ports", () => {
  for (const ok of ["backend.example.com", "a-1.svc.example.org"]) assert.ok(isHostname(ok), ok);
  for (const bad of ["Example.com", "localhost", "1.2.3.4", "a..b.com", "-a.example", "a_b.example.com", "a.example.123"])
    assert.ok(!isHostname(bad), bad);
  assert.ok(portIn("443,2000-2999", 2500));
  assert.ok(!portIn("443,2000-2999", 3000));
  assert.equal(targetPorts({ port: 3000, port_last: 3999 }), "3000-3999");
  assert.equal(targetPorts({ port: 443 }), "443");
  assert.equal(duplicatePorts("443", ["443", "444", "445-450"]), "451");
  assert.equal(duplicatePorts("2000-2099", ["2000-2099", "2150"]), "2151-2250");
});

test("saved order sorts, keeps new items last and merges filtered moves", () => {
  const items = ["a", "b", "c", "d"];
  assert.deepEqual(applyOrder(items, ["c", "a"], (x) => x), ["c", "a", "b", "d"]);
  assert.deepEqual(applyOrder(items, undefined, (x) => x), items);
  // Only b and d were visible (a filter); swapping them keeps a and c in place.
  assert.deepEqual(mergeOrder(items, ["b", "d"], ["d", "b"]), ["a", "d", "c", "b"]);
});

test("search finds a port inside a range and resolved addresses", () => {
  const rows = [
    { id: "F1", name: "Game", engine: "nftables", ports: "2000-2999", enabled: true, targets: [{ ip: "game.example.com" }], resolved: [{ ip: "203.0.113.9" }] },
    { id: "F2", name: "Web", engine: "haproxy", ports: "443", enabled: true, targets: [{ ip: "198.51.100.1" }] },
  ];
  assert.deepEqual(filterConnections(rows, { query: "2500" }).map((r) => r.id), ["F1"]);
  assert.deepEqual(filterConnections(rows, { query: "203.0.113.9" }).map((r) => r.id), ["F1"]);
  assert.deepEqual(filterConnections(rows, { query: "443" }).map((r) => r.id), ["F2"]);
});
