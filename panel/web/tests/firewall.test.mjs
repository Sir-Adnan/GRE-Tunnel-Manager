import test from "node:test";
import assert from "node:assert/strict";
import {
  accessProblem,
  blockedFor,
  findings,
  parseSources,
  sameSettings,
  withAccess,
  withUFW,
} from "../src/features/firewall/model.ts";

const settings = {
  private_ranges: false,
  smtp: false,
  exceptions: [],
  access: [],
  ufw: [],
};
const status = (extra = {}) => ({
  revision: "none",
  nft: true,
  ufw: { state: "active", incoming: "deny", routed: "deny" },
  docker: true,
  backends: [],
  tables: [],
  uplinks: ["eth0"],
  ssh: [22],
  auto_exceptions: [],
  ports: [],
  counters: [],
  settings,
  ...extra,
});
const kernel = {
  id: "F000001",
  name: "Kernel",
  engine: "nftables",
  protocol: "tcp",
  bind: "0.0.0.0",
  ports: "443",
  enabled: true,
};
const relay = {
  id: "F000002",
  name: "Relay",
  engine: "haproxy",
  protocol: "tcp",
  bind: "0.0.0.0",
  ports: "8443",
  enabled: true,
};

test("a dropping backend without the owned accept blocks kernel forwards of its family only", () => {
  const backends = [
    {
      family: 4,
      tool: "iptables-legacy",
      kind: "legacy",
      input: "DROP",
      forward: "DROP",
      guard: false,
    },
    {
      family: 6,
      tool: "ip6tables",
      kind: "nf_tables",
      input: "ACCEPT",
      forward: "DROP",
      guard: false,
    },
  ];
  const out = findings(status({ backends }), [kernel, relay]);
  assert.deepEqual(
    out.map((f) => [f.key, f.vars.tool, f.fix]),
    [["fwGuardMissing", "iptables-legacy", "repair"]],
  );
  // Installed accept, or no kernel forward of that family: nothing to report.
  backends[0].guard = true;
  assert.equal(findings(status({ backends }), [kernel]).length, 0);
});

test("closed relay ports matter only while UFW drops incoming traffic", () => {
  const ports = [
    { id: "F000001", protocol: "tcp", port: "443", ufw: "closed" },
    { id: "F000002", protocol: "tcp", port: "8443", ufw: "closed" },
  ];
  const out = findings(status({ ports }), [kernel, relay]);
  assert.deepEqual(
    out.map((f) => [f.key, f.connection, f.vars.p]),
    [["fwRelayClosed", "F000002", "8443/tcp"]],
  );
  assert.equal(
    findings(
      status({
        ports,
        ufw: { state: "inactive", incoming: "deny", routed: "deny" },
      }),
      [relay],
    ).length,
    0,
  );
  assert.equal(
    findings(
      status({
        ports,
        ufw: { state: "active", incoming: "allow", routed: "deny" },
      }),
      [relay],
    ).length,
    0,
  );
  assert.equal(
    findings(status({ ports }), [{ ...relay, enabled: false }]).length,
    0,
  );
});

test("unloaded rules and a missing nftables are problems; firewalld is a warning", () => {
  const wanted = { ...settings, smtp: true };
  const keys = findings(
    status({
      applied: false,
      nft: false,
      settings: wanted,
      firewalld: "active",
    }),
    [],
  ).map((f) => f.key);
  assert.deepEqual(keys, ["fwNotApplied", "fwNoNft", "fwFirewalld"]);
});

test("sources parse, deduplicate and report invalid words", () => {
  const { sources, invalid } = parseSources(
    "203.0.113.7, 198.51.100.0/24\n2001:db8::/32 203.0.113.7 example.com 10.0.0.0/33 0.0.0.0/0 ::",
  );
  assert.deepEqual(sources, [
    "203.0.113.7",
    "198.51.100.0/24",
    "2001:db8::/32",
  ]);
  assert.deepEqual(invalid, ["example.com", "10.0.0.0/33", "0.0.0.0/0", "::"]);
});

test("an allow list needs a source of the connection's family", () => {
  const a = {
    id: "F000001",
    mode: "allow",
    sources: ["2001:db8::/32"],
    per_ip: 0,
    rate: 0,
  };
  assert.equal(accessProblem(a, "0.0.0.0").key, "fwSourcesFamily");
  assert.equal(accessProblem(a, "2001:db8::1"), undefined);
  assert.equal(
    accessProblem({ ...a, sources: [] }, "0.0.0.0").key,
    "fwSourcesNeeded",
  );
  assert.equal(accessProblem({ ...a, mode: "deny" }, "0.0.0.0"), undefined);
  assert.equal(
    accessProblem({ ...a, mode: "off", sources: [] }, "0.0.0.0"),
    undefined,
  );
});

test("edits keep only meaningful entries and compare by meaning", () => {
  let s = withAccess(settings, {
    id: "F000001",
    mode: "deny",
    sources: ["203.0.113.7"],
    per_ip: 0,
    rate: 0,
  });
  s = withUFW(s, "F000002", true);
  assert.equal(s.access.length, 1);
  assert.ok(!sameSettings(s, settings));
  const back = withUFW(
    withAccess(s, {
      id: "F000001",
      mode: "off",
      sources: ["x"],
      per_ip: 0,
      rate: 0,
    }),
    "F000002",
    false,
  );
  assert.equal(back.access.length, 0);
  assert.ok(sameSettings(back, settings));
  // Limits without a list keep the entry; its sources are cleared.
  const limited = withAccess(settings, {
    id: "F000001",
    mode: "off",
    sources: ["203.0.113.7"],
    per_ip: 20,
    rate: 0,
  });
  assert.deepEqual(limited.access[0].sources, []);
  const reordered = {
    ...s,
    ufw: [...s.ufw].reverse(),
    access: [...s.access].reverse(),
  };
  assert.ok(sameSettings(s, reordered));
});

test("blocked packets sum a connection's own counters", () => {
  const counters = [
    { rule: "F000001-allow", packets: 10, bytes: 0 },
    { rule: "F000001-rate", packets: 5, bytes: 0 },
    { rule: "F0000011-deny", packets: 99, bytes: 0 },
    { rule: "private", packets: 7, bytes: 0 },
  ];
  assert.equal(blockedFor(status({ counters }), "F000001"), 15);
});
