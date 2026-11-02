import test from "node:test";
import assert from "node:assert/strict";
import { parseRoute, routeURL } from "../src/lib/navigation.ts";

test("embedded-server routes survive a direct link with Unicode search and scoped details", () => {
  const params = new URLSearchParams({
    q: "تهران & Frankfurt",
    status: "configured",
    connection: "F000003",
    detail: "destinations",
  });
  const hash = routeURL("connections", params);
  const route = parseRoute(hash);
  assert.equal(route.page, "connections");
  assert.deepEqual([...route.params], [...params]);
  assert.ok(hash.startsWith("#/connections?"));
});

test("v1.3 engine pages open the merged Connections page with their filter", () => {
  for (const [page, engine] of [
    ["forwarding", "kernel"],
    ["haproxy", "haproxy"],
    ["realm", "realm"],
  ]) {
    const route = parseRoute(`#/${page}?q=edge`);
    assert.equal(route.page, "connections");
    assert.equal(route.params.get("engine"), engine);
    assert.equal(route.params.get("q"), "edge");
    assert.equal(routeURL(page), `#/connections?engine=${engine}`);
  }
  // An explicit filter in an old link wins over the page's implied one.
  assert.equal(parseRoute("#/haproxy?engine=all").params.get("engine"), "all");
  // Prototype keys are not aliases.
  assert.equal(parseRoute("#/constructor").page, "overview");
});

test("unknown or external paths cannot become navigation destinations", () => {
  for (const hash of [
    "",
    "#/missing",
    "#//example.com",
    "#/<script>",
    "#/../api/operations",
  ]) {
    assert.equal(parseRoute(hash).page, "overview");
  }
  assert.equal(routeURL("https://example.com"), "#/overview");
  const traffic = parseRoute("#/traffic?tab=details&resource=F000003");
  assert.equal(traffic.params.get("resource"), "F000003");
  assert.equal(traffic.page, "traffic");
});
