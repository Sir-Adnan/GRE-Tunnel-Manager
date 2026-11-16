import test from "node:test";
import assert from "node:assert/strict";
import {
  createdConnection,
  pathView,
  silentDestinations,
} from "../src/features/check/model.ts";
import { connectionBadges } from "../src/features/check/badges.ts";
import { cleanError, errorKeys, explainError } from "../src/lib/error-help.ts";
import { availableTemplates, templateDraft } from "../src/lib/templates.ts";

const sample = (time, stages, extra = {}) => ({
  id: "F000001",
  engine: "nftables",
  enabled: true,
  time,
  stages,
  drops: [],
  ...extra,
});
const kernel = (n, out, back, out2 = out, back2 = back) => [
  { key: "new", packets: n, bytes: n * 60 },
  { key: "out", address: "203.0.113.20", packets: out, bytes: out * 100 },
  { key: "back", address: "203.0.113.20", packets: back, bytes: back * 1000 },
  { key: "out", address: "203.0.113.21", packets: out2, bytes: out2 * 100 },
  { key: "back", address: "203.0.113.21", packets: back2, bytes: back2 * 1000 },
];

test("the first sample judges totals, the next one rates", () => {
  const first = pathView(sample("2026-11-15T10:00:00Z", kernel(10, 500, 800)));
  assert.equal(first.live, false);
  assert.equal(first.verdict, "flowing");
  assert.equal(first.incoming.total, 10);
  assert.equal(first.destinations.length, 2);
  const prev = sample("2026-11-15T10:00:00Z", kernel(10, 500, 800));
  // Nothing moved for 3 s: quiet now even though totals are high.
  const idle = pathView(
    sample("2026-11-15T10:00:03Z", kernel(10, 500, 800)),
    prev,
  );
  assert.equal(idle.live, true);
  assert.equal(idle.verdict, "idle");
  const busy = pathView(
    sample("2026-11-15T10:00:03Z", kernel(16, 530, 860)),
    prev,
  );
  assert.equal(busy.verdict, "flowing");
  assert.equal(busy.incoming.rate, 2);
  assert.equal(busy.destinations[0].out.rate, 10);
  assert.equal(busy.destinations[0].back.byteRate, 20000);
});

test("the verdict names where traffic stops", () => {
  const prev = sample("2026-11-15T10:00:00Z", kernel(10, 500, 800));
  const at = "2026-11-15T10:00:03Z";
  assert.equal(
    pathView(sample(at, kernel(13, 500, 800)), prev).verdict,
    "stuck",
  );
  assert.equal(
    pathView(sample(at, kernel(13, 530, 800)), prev).verdict,
    "noAnswer",
  );
  const partial = pathView(sample(at, kernel(13, 530, 830, 520, 800)), prev);
  assert.equal(partial.verdict, "partial");
  assert.deepEqual(silentDestinations(partial), ["203.0.113.21"]);
  const dropped = pathView(
    sample(at, kernel(13, 530, 830), { drops: ["iptables-legacy"] }),
    prev,
  );
  assert.equal(dropped.verdict, "dropped");
  assert.equal(
    pathView(sample(at, [], { enabled: false }), prev).verdict,
    "disabled",
  );
  // Reapplied rules reset the counters: no rate rather than a negative one.
  const reset = pathView(sample(at, kernel(2, 30, 40)), prev);
  assert.equal(reset.incoming.rate, undefined);
  assert.equal(reset.live, true);
});

test("relays judge connected clients and upstream sockets", () => {
  const relay = (clients, upstream) =>
    pathView(
      sample(
        "2026-11-15T10:00:00Z",
        [
          { key: "clients", packets: clients, bytes: 0 },
          {
            key: "upstream",
            address: "203.0.113.30",
            packets: upstream,
            bytes: 0,
          },
        ],
        { engine: "haproxy" },
      ),
    );
  assert.equal(relay(0, 0).verdict, "idle");
  assert.equal(relay(3, 0).verdict, "noAnswer");
  assert.equal(relay(3, 3).verdict, "flowing");
  assert.equal(relay(3, 3).kernel, false);
  assert.equal(relay(3, 3).destinations[0].upstream, 3);
});

test("a create's new connection is the newest unknown ID", () => {
  assert.equal(
    createdConnection(
      ["F000001", "F000002"],
      [
        { id: "F000001" },
        { id: "F000005" },
        { id: "F000002" },
        { id: "F000003" },
      ],
    ),
    "F000005",
  );
  assert.equal(createdConnection(["F000001"], [{ id: "F000001" }]), undefined);
});

const status = (extra = {}) => ({
  revision: "none",
  nft: true,
  ufw: { state: "active", incoming: "deny", routed: "deny" },
  docker: false,
  backends: [
    {
      family: 4,
      tool: "iptables-legacy",
      kind: "legacy",
      input: "DROP",
      forward: "DROP",
      guard: false,
    },
  ],
  tables: [],
  uplinks: ["eth0"],
  ssh: [22],
  auto_exceptions: [],
  ports: [{ id: "F000002", protocol: "tcp", port: "443", ufw: "closed" }],
  counters: [],
  settings: {
    private_ranges: false,
    smtp: false,
    exceptions: [],
    access: [
      {
        id: "F000001",
        mode: "allow",
        sources: ["198.51.100.0/24", "203.0.113.9/32"],
        per_ip: 0,
        rate: 0,
      },
    ],
    ufw: [],
  },
  ...extra,
});

test("badges show the source address and the firewall's effect", () => {
  const forward = {
    id: "F000001",
    engine: "nftables",
    bind: "0.0.0.0",
    snat: "masquerade",
    enabled: true,
  };
  assert.deepEqual(
    connectionBadges(forward).map((b) => b.key),
    ["cbSourceServer"],
  );
  assert.deepEqual(
    connectionBadges(forward, status()).map((b) => [b.key, b.count, b.tone]),
    [
      ["cbSourceServer", undefined, undefined],
      ["cbForwardBlocked", undefined, "problem"],
      ["cbAllow", 2, undefined],
    ],
  );
  // IPv6 forwards are not blocked by an IPv4 backend; disabled ones never are.
  assert.equal(
    connectionBadges({ ...forward, bind: "::" }, status()).some(
      (b) => b.key === "cbForwardBlocked",
    ),
    false,
  );
  const relay = {
    id: "F000002",
    engine: "haproxy",
    bind: "0.0.0.0",
    snat: "masquerade",
    enabled: true,
  };
  assert.deepEqual(
    connectionBadges(relay, status()).map((b) => b.key),
    ["cbUFWClosed"],
  );
  assert.deepEqual(
    connectionBadges(
      relay,
      status({ ufw: { state: "inactive", incoming: "", routed: "" } }),
    ),
    [],
  );
  assert.deepEqual(
    connectionBadges(
      { ...forward, snat: "none", enabled: false },
      status(),
    ).map((b) => b.key),
    ["cbSourceClient", "cbAllow"],
  );
});

test("errors keep the engine's words and gain a cause and a fix", () => {
  const dns =
    "operation failed: exit status 1: Error: The resolver reports global DNS 'none' instead of the selected servers.\nError: DNS change failed; the previous configuration was restored.";
  assert.deepEqual(cleanError(dns), [
    "The resolver reports global DNS 'none' instead of the selected servers.",
    "DNS change failed; the previous configuration was restored.",
  ]);
  assert.deepEqual(explainError(dns), {
    key: "serverDNS",
    page: "optimize",
    params: { tab: "dns" },
  });
  assert.equal(
    explainError(
      "operation failed: exit status 1: Error: A local service already uses the requested address/port: 0.0.0.0:443",
    ).key,
    "portInUse",
  );
  assert.equal(
    explainError("selection changed; refresh the list").reload,
    true,
  );
  assert.equal(
    explainError("Error: UFW is not installed; ports were not opened.").page,
    "firewall",
  );
  assert.equal(
    explainError("Error: Install the required tool first: haproxy").page,
    "components",
  );
  assert.deepEqual(errorKeys("something odd"), {
    title: "ehUnknown",
    fix: "ehUnknownFix",
    help: undefined,
  });
});

const inventory = (installed, resources = []) => ({
  connections: [],
  resources,
  components: ["nftables", "iptables", "haproxy", "realm"].map((id) => ({
    id,
    installed: installed.includes(id),
  })),
  capabilities: [],
  host: {
    hostname: "edge",
    os: "",
    addresses: [],
    uptime: "",
    memory_total: 0,
    memory_available: 0,
    load: "",
  },
  version: "",
  demo: true,
});

test("templates fill a common setup with the engines that are there", () => {
  const all = inventory(["nftables", "iptables", "haproxy", "realm"]);
  assert.deepEqual(availableTemplates(all), ["vpn", "web", "range", "balance"]);
  const vpn = templateDraft("vpn", all);
  assert.equal(vpn.engine, "nftables");
  assert.equal(vpn.protocol, "both");
  assert.equal(
    templateDraft("vpn", inventory(["iptables"])).engine,
    "iptables",
  );
  assert.equal(templateDraft("vpn", inventory(["realm"])).engine, "realm");
  assert.equal(templateDraft("range", all).port_mode, "same");
  assert.equal(templateDraft("balance", all).targets.length, 2);
  // A GRE tunnel adds its template, aimed at the far end's inner address.
  const gre = inventory(
    ["nftables"],
    [
      {
        id: "gre-tun-3",
        engine: "gre",
        name: "GRE 3",
        role: "",
        status: "",
        description: "",
        configured: true,
        peer: "10.0.3.2",
      },
    ],
  );
  assert.ok(availableTemplates(gre).includes("gre"));
  assert.equal(templateDraft("gre", gre).targets[0].ip, "10.0.3.2");
  // A HAProxy-only page offers only relay templates.
  assert.deepEqual(availableTemplates(all, ["haproxy"]), ["web", "balance"]);
  assert.equal(templateDraft("vpn", all, ["realm"]).engine, "realm");
});
