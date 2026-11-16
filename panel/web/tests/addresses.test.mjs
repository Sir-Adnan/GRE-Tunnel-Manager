import test from "node:test";
import assert from "node:assert/strict";
import {
  extraProblem,
  manualPeers,
  newChoices,
  oldChoices,
  parseExtraResult,
  parseResults,
  partnerNode,
  peerCommand,
  staleLocal,
  usableAddress,
  versionAtLeast,
  withPrefix,
} from "../src/features/addresses/model.ts";
import { attentionItems } from "../src/lib/attention.ts";

const usage = (u, address, kind, id, extra = {}) => ({
  use: u,
  address,
  kind,
  id,
  name: id,
  present: false,
  editable: true,
  ...extra,
});
const report = {
  addresses: [
    {
      interface: "eth0",
      address: "203.0.113.10",
      prefix: 24,
      uplink: true,
      container: false,
    },
    {
      interface: "eth0",
      address: "2001:db8::10",
      prefix: 64,
      uplink: true,
      container: false,
    },
    {
      interface: "docker0",
      address: "172.17.0.1",
      prefix: 16,
      uplink: false,
      container: true,
    },
  ],
  uplink: "eth0",
  gateway: "203.0.113.1",
  interfaces: ["eth0"],
  uses: [
    usage("local", "203.0.113.5", "gre", "gre-tun-7"),
    usage("remote", "198.51.100.70", "gre", "gre-tun-7"),
    usage("local", "203.0.113.5", "gre", "gre-tun-8"),
    usage("remote", "198.51.100.80", "gre", "gre-tun-8"),
    usage("local", "203.0.113.10", "connection", "F000001", { present: true }),
    usage("remote", "198.51.100.20", "connection", "F000001"),
  ],
  stale: ["203.0.113.5"],
  suggested: "203.0.113.10",
  extra: [],
};

test("addresses are literal, usable and unambiguous", () => {
  for (const ok of ["203.0.113.5", "2001:db8::10", "2001:db8:0:0:0:0:0:1"])
    assert.equal(usableAddress(ok), true, ok);
  for (const bad of [
    "0.0.0.0",
    "127.0.0.1",
    "::",
    "::1",
    "fe80::1",
    "1.2.3",
    "2001:db8::1::2",
    "example.com",
    "203.0.113.256",
    "",
  ])
    assert.equal(usableAddress(bad), false, bad);
  assert.equal(withPrefix("203.0.113.40"), "203.0.113.40/32");
  assert.equal(withPrefix("2001:db8::40"), "2001:db8::40/128");
  assert.equal(withPrefix("203.0.113.40/24"), "203.0.113.40/24");
});

test("a lost address is found from inventory alone and leads the attention list", () => {
  const inventory = {
    host: { addresses: ["203.0.113.10"] },
    connections: [
      {
        id: "F1",
        name: "A",
        engine: "haproxy",
        enabled: true,
        status: "failed",
        bind: "203.0.113.5",
      },
      {
        id: "F2",
        name: "B",
        engine: "nftables",
        enabled: true,
        bind: "0.0.0.0",
      },
      {
        id: "F3",
        name: "C",
        engine: "nftables",
        enabled: true,
        bind: "127.0.0.1",
      },
    ],
    resources: [
      {
        id: "gre-tun-7",
        name: "GRE 7",
        engine: "gre",
        status: "active",
        configured: true,
        bind: "203.0.113.5",
      },
      {
        id: "gtm-frp-entrance-x",
        name: "x",
        engine: "frp",
        status: "active",
        configured: true,
        bind: "203.0.113.99",
      },
    ],
    components: [],
  };
  assert.deepEqual(staleLocal(inventory), ["203.0.113.5"]);
  const items = attentionItems(inventory);
  assert.deepEqual(items[0], {
    kind: "address",
    id: "203.0.113.5",
    name: "203.0.113.5",
    detail: "addressGone",
  });
  assert.equal(items.filter((i) => i.kind === "address").length, 1);
  // Without host information (older callers) nothing about addresses is inferred.
  const { host: _host, ...withoutHost } = inventory;
  assert.equal(
    attentionItems(withoutHost).some((i) => i.kind === "address"),
    false,
  );
});

test("old and new choices follow the address family and skip container bridges", () => {
  assert.deepEqual(oldChoices(report, "local"), [
    "203.0.113.5",
    "203.0.113.10",
  ]);
  assert.deepEqual(oldChoices(report, "remote"), [
    "198.51.100.70",
    "198.51.100.80",
    "198.51.100.20",
  ]);
  assert.deepEqual(newChoices(report, "203.0.113.5"), ["203.0.113.10"]);
  assert.deepEqual(newChoices(report, "2001:db8::5"), ["2001:db8::10"]);
});

const node = (extra = {}) => ({
  id: "n1",
  name: "Frankfurt",
  revision: "r1",
  local: false,
  status: "online",
  version: "1.6.0",
  capabilities: ["inventory.read", "connections.pair.v1"],
  inventory: {
    resources: [
      {
        id: "gre-tun-7",
        engine: "gre",
        bind: "198.51.100.70",
        remote: "203.0.113.5",
      },
      {
        id: "gre-tun-9",
        engine: "gre",
        bind: "198.51.100.70",
        remote: "203.0.113.99",
      },
    ],
  },
  ...extra,
});

test("the Node at the other end of a tunnel moves its side; other peers get the command", () => {
  const gre = report.uses.filter((u) => u.use === "local" && u.kind === "gre");
  const local = { ...node(), id: "local", local: true };
  const partner = partnerNode([local, node()], gre, "local", "203.0.113.5");
  assert.equal(partner.node.id, "n1");
  assert.deepEqual(partner.ids, ["gre-tun-7"]);
  assert.equal(partner.blocked, "");
  const remotes = {
    "gre-tun-7": "198.51.100.70",
    "gre-tun-8": "198.51.100.80",
  };
  assert.deepEqual(manualPeers(gre, remotes, partner), ["198.51.100.80"]);
  assert.deepEqual(manualPeers(gre, remotes, undefined), [
    "198.51.100.70",
    "198.51.100.80",
  ]);

  assert.equal(
    partnerNode([node({ version: "1.5.3" })], gre, "local", "203.0.113.5")
      .blocked,
    "agentOutdated",
  );
  assert.equal(
    partnerNode([node({ status: "offline" })], gre, "local", "203.0.113.5")
      .blocked,
    "nodeOffline",
  );
  assert.equal(
    partnerNode(
      [node({ capabilities: ["inventory.read"] })],
      gre,
      "local",
      "203.0.113.5",
    ).blocked,
    "nodeOffline",
  );
  // A blocked Node does not cover its tunnels.
  const old = partnerNode(
    [node({ version: "1.4.0" })],
    gre,
    "local",
    "203.0.113.5",
  );
  assert.deepEqual(manualPeers(gre, remotes, old), [
    "198.51.100.70",
    "198.51.100.80",
  ]);

  // Another server's address changed: the Node whose tunnel end was that address.
  const remoteGre = [usage("remote", "198.51.100.70", "gre", "gre-tun-7")];
  assert.equal(
    partnerNode([node()], remoteGre, "remote", "198.51.100.70").node.id,
    "n1",
  );
  assert.equal(
    partnerNode([node()], remoteGre, "remote", "198.51.100.71"),
    undefined,
  );
});

test("Agent versions compare numerically", () => {
  for (const [v, want] of [
    ["1.6.0", true],
    ["1.6.10", true],
    ["2.0.0", true],
    ["1.6.0-rc1", true],
    ["1.5.4", false],
    ["1.4.99", false],
    ["", false],
    ["dev", false],
  ])
    assert.equal(versionAtLeast(v), want, v);
});

test("engine results are read from output and from error text", () => {
  assert.deepEqual(
    parseResults("Demo\nresult\tgre-tun-7\tdone\nresult\tF000001\tfailed\n"),
    {
      "gre-tun-7": "done",
      F000001: "failed",
    },
  );
  assert.deepEqual(parseResults("exit status 1: result\tF000002\tfailed"), {
    F000002: "failed",
  });
  assert.deepEqual(parseResults("nothing here"), {});
  assert.deepEqual(
    parseExtraResult("extra\t3\ncheck\tpresent\t1\ncheck\troute\t0"),
    { id: 3, present: true, route: false },
  );
  assert.equal(
    peerCommand("203.0.113.5", "203.0.113.10", "remote"),
    "sudo bash gre.sh --api address-replace 203.0.113.5 203.0.113.10 remote all",
  );
});

test("additional addresses are checked before anything runs", () => {
  const host = report.addresses;
  assert.equal(extraProblem("203.0.113.40/32", "", host), "");
  assert.equal(extraProblem("203.0.113.40", "", host), "");
  assert.equal(extraProblem("203.0.113.40/24", "203.0.113.1", host), "");
  assert.equal(extraProblem("203.0.113.10/32", "", host), "ipExtraExists");
  assert.equal(extraProblem("203.0.113.40/4", "", host), "ipExtraBadPrefix");
  assert.equal(extraProblem("203.0.113.40/33", "", host), "ipExtraBadPrefix");
  assert.equal(extraProblem("2001:db8::40/64", "", host), "");
  assert.equal(extraProblem("not-an-ip", "", host), "ipExtraBadAddress");
  assert.equal(
    extraProblem("203.0.113.40/32", "2001:db8::1", host),
    "ipExtraBadGateway",
  );
  assert.equal(
    extraProblem("203.0.113.40/32/1", "", host),
    "ipExtraBadAddress",
  );
});
