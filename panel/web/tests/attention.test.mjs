import test from "node:test";
import assert from "node:assert/strict";
import { attentionItems } from "../src/lib/attention.ts";

test("only enabled services in a failing state and missing engines need attention", () => {
  const items = attentionItems({
    connections: [
      {
        id: "H1",
        name: "Edge",
        engine: "haproxy",
        enabled: true,
        status: "failed",
      },
      {
        id: "H2",
        name: "Off",
        engine: "haproxy",
        enabled: false,
        status: "inactive",
      },
      {
        id: "N1",
        name: "Kernel",
        engine: "nftables",
        enabled: true,
        status: "configured",
      },
      {
        id: "R1",
        name: "Relay",
        engine: "realm",
        enabled: true,
        status: "active",
      },
    ],
    resources: [
      { id: "gre-1", name: "GRE 1", status: "inactive", configured: true },
      { id: "gre-2", name: "GRE 2", status: "inactive", configured: false },
      { id: "gre-3", name: "GRE 3", status: "active", configured: true },
    ],
    components: [
      { id: "haproxy", installed: true },
      { id: "realm", installed: false },
    ],
  });
  assert.deepEqual(
    items.map((item) => `${item.kind}:${item.id}:${item.detail}`),
    ["connection:H1:failed", "resource:gre-1:inactive", "engine:realm:realm"],
  );
});

test("a healthy server has nothing to report", () => {
  assert.deepEqual(
    attentionItems({ connections: [], resources: [], components: [] }),
    [],
  );
});
