import test from "node:test";
import assert from "node:assert/strict";
import { parseRoute, routeURL } from "../src/lib/navigation.ts";

test("embedded-server routes survive a direct link with Unicode search and scoped details", () => {
  const params = new URLSearchParams({ q: "تهران & Frankfurt", status: "configured", connection: "F000003", detail: "destinations" });
  const hash = routeURL("haproxy", params);
  const route = parseRoute(hash);
  assert.equal(route.page, "haproxy");
  assert.deepEqual([...route.params], [...params]);
  assert.ok(hash.startsWith("#/haproxy?"));
});

test("unknown or external paths cannot become navigation destinations", () => {
  for (const hash of ["", "#/missing", "#//example.com", "#/<script>", "#/../api/operations"]) {
    assert.equal(parseRoute(hash).page, "overview");
  }
  assert.equal(routeURL("https://example.com"), "#/overview");
  const traffic = parseRoute("#/traffic?tab=details&resource=F000003");
  assert.equal(traffic.params.get("resource"), "F000003");
  assert.equal(traffic.page, "traffic");
});
