import test from "node:test";
import assert from "node:assert/strict";
import {
  defaultName,
  farSide,
  forwardConnection,
  freeTunnelID,
  greRequest,
  maxMTU,
  portOwner,
  tunnelAddresses,
  validIP,
  wizardDefaults,
  wizardErrors,
} from "../src/features/wizard/model.ts";

const inventory = (extra = {}) => ({
  host: { addresses: ["203.0.113.10", "2001:db8::10"], hostname: "edge" },
  resources: [
    { id: "gre-tun-1", engine: "gre" },
    { id: "gre-tun-3", engine: "gre" },
    { id: "gtm-frp-entrance-a", engine: "frp" },
  ],
  connections: [{ id: "F000001", protocol: "tcp", ports: "8443" }],
  components: [{ id: "nftables", installed: true }],
  ...extra,
});
const options = (engine) => ({ engine });

test("defaults pick this server's IPv4 address and a free tunnel ID", () => {
  const draft = wizardDefaults(inventory());
  assert.equal(draft.bind, "203.0.113.10");
  assert.equal(draft.id, 2);
  assert.equal(draft.forward, true);
  const full = inventory({
    resources: Array.from({ length: 250 }, (_, i) => ({
      id: `gre-tun-${i + 1}`,
      engine: "gre",
    })),
  });
  assert.equal(freeTunnelID(full), 0);
  assert.deepEqual(tunnelAddresses(7), {
    entrance: "10.0.7.2",
    foreign: "10.0.7.1",
  });
  assert.equal(maxMTU("2001:db8::1"), 1452);
});

test("tunnel step checks addresses, family, ID and MTU", () => {
  const inv = inventory();
  const draft = { ...wizardDefaults(inv), remote: "198.51.100.20" };
  assert.deepEqual(wizardErrors(draft, inv, 0), {});
  assert.equal(
    wizardErrors({ ...draft, remote: "" }, inv, 0).remote,
    "wizErrorAddress",
  );
  assert.equal(
    wizardErrors({ ...draft, remote: "300.1.1.1" }, inv, 0).remote,
    "wizErrorAddress",
  );
  assert.equal(
    wizardErrors({ ...draft, remote: draft.bind }, inv, 0).remote,
    "wizErrorSameServer",
  );
  assert.equal(
    wizardErrors({ ...draft, remote: "2001:db8::20" }, inv, 0).bind,
    "wizErrorFamily",
  );
  assert.equal(wizardErrors({ ...draft, id: 3 }, inv, 0).id, "wizErrorIDUsed");
  assert.equal(wizardErrors({ ...draft, id: 251 }, inv, 0).id, "wizErrorID");
  assert.equal(
    wizardErrors({ ...draft, mtu: 1473 }, inv, 0).mtu,
    "wizErrorMTU",
  );
  assert.ok(validIP("2001:db8::20"));
  assert.ok(!validIP("2001:db8::zz"));
});

test("forward step checks ports and conflicts by protocol", () => {
  const inv = inventory();
  const draft = { ...wizardDefaults(inv), remote: "198.51.100.20" };
  assert.deepEqual(wizardErrors(draft, inv, 1), {});
  assert.equal(
    wizardErrors({ ...draft, ports: "" }, inv, 1).ports,
    "portsError_empty",
  );
  assert.equal(
    wizardErrors({ ...draft, ports: "70000" }, inv, 1).ports,
    "portsError_invalid",
  );
  assert.equal(
    wizardErrors({ ...draft, ports: "8000-9000" }, inv, 1).ports,
    "wizErrorPortUsed",
  );
  // UDP does not clash with a TCP-only listener.
  assert.equal(portOwner({ ports: "8443", protocol: "udp" }, inv), undefined);
  // Tunnel only: ports are not checked.
  assert.deepEqual(
    wizardErrors({ ...draft, ports: "", forward: false }, inv, 1),
    {},
  );
});

test("requests: this server is Side B, the far side mirrors it", () => {
  const inv = inventory();
  const draft = {
    ...wizardDefaults(inv),
    remote: " 198.51.100.20 ",
    ports: "443, 2000-2100",
  };
  assert.deepEqual(greRequest(draft), {
    id: 2,
    role: "iran",
    remote: "198.51.100.20",
    bind: "203.0.113.10",
    mtu: 1430,
  });
  assert.deepEqual(farSide(draft), {
    id: 2,
    role: "kharej",
    remote: "203.0.113.10",
    bind: "198.51.100.20",
    mtu: 1430,
  });
  const c = forwardConnection(draft, inv, options);
  assert.equal(c.engine, "nftables");
  assert.equal(c.ports, "443,2000-2100");
  assert.equal(c.port_mode, "same");
  assert.equal(c.protocol, "both");
  assert.deepEqual(c.targets, [{ ip: "10.0.2.1", port: 443, weight: 1 }]);
  assert.deepEqual(c.options, { engine: "nftables" });
  assert.equal(c.name, "GRE 2");
  assert.equal(defaultName(5, " 8443 "), "GRE 5 8443");
  assert.equal(defaultName(5, "443, 8443"), "GRE 5");
  assert.equal(
    forwardConnection({ ...draft, ports: "2000-2100" }, inv, options).name,
    "GRE 2 2000-2100",
  );
  assert.equal(
    wizardErrors({ ...draft, name: "مسیر" }, inv, 1).name,
    "wizErrorName",
  );
  assert.deepEqual(
    wizardErrors({ ...draft, name: "Edge_1.web-2" }, inv, 1),
    {},
  );
  const one = forwardConnection(
    { ...draft, ports: "8080", name: " Web " },
    inv,
    options,
  );
  assert.equal(one.port_mode, "");
  assert.equal(one.name, "Web");
  assert.equal(one.targets[0].port, 8080);
});
