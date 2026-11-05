import test from "node:test";
import assert from "node:assert/strict";
import {
  compactValue,
  customValid,
  flowTableBytes,
  goals,
  groupStates,
  groups,
  keyLabel,
  levels,
  managedKeys,
  outagesSinceApply,
  pendingChanges,
  recommendedGroups,
  serverFit,
} from "../src/features/optimize/catalog.ts";
import { optimize } from "../src/lib/i18n/messages/optimize.ts";

const view = {
  memory: 1073741824,
  flows: 1200,
  congestion: ["cubic", "bbr"],
  steps: 1,
  file: "/etc/sysctl.d/zz-gre-manager-optimize.conf",
  servertools: [],
  keys: [
    {
      group: "conntrack",
      key: "net.netfilter.nf_conntrack_max",
      current: "131072",
      before: "65536",
      applied: "131072",
      recommended: "131072",
      note: "same",
    },
    {
      group: "conntrack",
      key: "net.netfilter.nf_conntrack_udp_timeout",
      current: "90",
      before: "30",
      applied: "60",
      recommended: "90",
      note: "kept",
    },
    {
      group: "queues",
      key: "net.core.somaxconn",
      current: "4096",
      recommended: "8192",
      note: "change",
    },
    {
      group: "relay",
      key: "net.core.default_qdisc",
      current: "cake",
      recommended: "cake",
      note: "kept",
    },
    {
      group: "routing",
      key: "net.ipv4.conf.all.rp_filter",
      current: "1",
      recommended: "2",
      note: "change",
    },
  ],
};

test("group states count managed, drifted, pending and kept settings", () => {
  const states = groupStates(view);
  assert.deepEqual(
    states.map((s) => [
      s.group,
      s.applied,
      s.drifted,
      s.pending,
      s.kept,
      s.status,
    ]),
    [
      ["conntrack", 2, 1, 0, 1, "applied"],
      ["queues", 0, 0, 1, 0, "available"],
      ["relay", 0, 0, 0, 1, "current"],
      ["routing", 0, 0, 1, 0, "available"],
    ],
  );
  assert.equal(managedKeys(view).length, 2);
});

test("recommendations follow what the server runs", () => {
  const inventory = {
    connections: [
      { engine: "nftables", enabled: true },
      { engine: "haproxy", enabled: false },
    ],
    resources: [{ engine: "gre" }],
    host: { addresses: ["203.0.113.10", "2001:db8::10"] },
  };
  const fit = serverFit(inventory, view);
  assert.deepEqual([...fit].sort(), ["conntrack", "routing"]);
  assert.deepEqual(recommendedGroups(groupStates(view), fit), ["routing"]);
  const busy = serverFit(
    { ...inventory, resources: [] },
    { ...view, flows: 50000 },
  );
  assert.deepEqual([...busy].sort(), ["conntrack", "queues"]);
});

test("values are compact and only real changes count as pending", () => {
  assert.equal(
    compactValue(
      "net.netfilter.nf_conntrack_tcp_timeout_established",
      "432000",
    ),
    "5d",
  );
  assert.equal(compactValue("net.ipv4.tcp_keepalive_time", "630"), "10m 30s");
  assert.equal(compactValue("net.core.rmem_max", "212992"), "208 KiB");
  assert.equal(
    compactValue("net.ipv4.tcp_rmem", "4096 131072 33554432"),
    "4 KiB · 128 KiB · 32 MiB",
  );
  assert.equal(compactValue("net.ipv4.tcp_notsent_lowat", "4294967295"), "∞");
  assert.equal(compactValue("net.ipv4.conf.all.rp_filter", "2"), "loose");
  assert.equal(compactValue("net.core.default_qdisc", "fq"), "fq");
  assert.equal(compactValue("net.core.somaxconn", undefined), "—");
  assert.equal(flowTableBytes(131072, 65536), 131072 * 350 + 65536 * 8);
  const changes = ["change", "same", "kept", "missing"].map((note, i) => ({
    group: "relay",
    key: String(i),
    value: "1",
    reason: "bbr",
    note,
  }));
  assert.deepEqual(
    pendingChanges(changes).map((c) => c.key),
    ["0"],
  );
  const custom = ["custom", "worse", "off"].map((note) => ({
    group: "relay",
    key: note,
    value: "1",
    reason: "bbr",
    note,
  }));
  assert.deepEqual(
    pendingChanges(custom).map((c) => c.key),
    ["custom", "worse"],
  );
  assert.equal(
    compactValue("net.ipv4.ip_local_port_range", "16384 65535"),
    "16384–65535",
  );
});

test("custom values follow the bounds the server sent", () => {
  const number = { kind: "number", min: 5, max: 60 };
  assert.ok(customValid(number, "15"));
  assert.ok(!customValid(number, "61"));
  assert.ok(!customValid(number, "1 2"));
  assert.ok(!customValid(number, "1e3"));
  const triple = { kind: "triple", min: 4096, max: 268435456 };
  assert.ok(customValid(triple, "4096 131072 67108864"));
  assert.ok(!customValid(triple, "8192 4096 33554432"));
  assert.ok(!customValid(triple, "4096 131072"));
  const range = { kind: "range", min: 1024, max: 65535 };
  assert.ok(customValid(range, "16384 65535"));
  assert.ok(!customValid(range, "2000 2000"));
  assert.ok(!customValid(range, "80 2000"));
  const choice = { kind: "choice", choices: ["fq", "cake"] };
  assert.ok(customValid(choice, "cake"));
  assert.ok(!customValid(choice, "pfifo"));
  assert.ok(!customValid({}, "1"));
});

test("outages after a recent apply suggest undoing it", () => {
  const last = Date.parse("2026-11-05T10:00:00Z") / 1000;
  const health = {
    settings: { enabled: true },
    outages: [
      { name: "before", start: "2026-11-05T09:30:00Z" },
      { name: "after", start: "2026-11-05T10:20:00Z" },
    ],
  };
  const now = Date.parse("2026-11-05T11:00:00Z");
  assert.deepEqual(
    outagesSinceApply({ last, steps: 1 }, health, now).map((o) => o.name),
    ["after"],
  );
  assert.equal(outagesSinceApply({ last, steps: 0 }, health, now).length, 0);
  assert.equal(
    outagesSinceApply({ last, steps: 1 }, health, now + 86400000).length,
    0,
  );
  assert.equal(
    outagesSinceApply(
      { last, steps: 1 },
      { ...health, settings: { enabled: false } },
      now,
    ).length,
    0,
  );
});

test("every group, key label and reason has both languages", () => {
  const reasons = [
    "flow-limit",
    "flow-buckets",
    "idle-tcp",
    "closing-tcp",
    "udp",
    "udp-stream",
    "backlog",
    "budget",
    "accept-queue",
    "syn-queue",
    "pacing",
    "bbr",
    "buffers",
    "notsent",
    "mtu-probing",
    "idle-restart",
    "keepalive",
    "fin-timeout",
    "tw-reuse",
    "rp-filter",
    "redirects",
    "accept-redirects",
    "ports",
    "tw-buckets",
  ];
  const keys = [
    ...groups.flatMap((g) => [
      `optGroup_${g}`,
      `optGroupWhy_${g}`,
      `optGroupFor_${g}`,
    ]),
    ...Object.values(keyLabel),
    ...reasons.map((r) => `optWhy_${r}`),
    ...levels.flatMap((l) => [`optLevel_${l}`, `optLevelWhy_${l}`]),
    ...goals.flatMap((g) => [`optGoal_${g}`, `optGoalWhy_${g}`]),
    "optAllowed",
    "optAllowed_triple",
    "optAllowed_range",
  ];
  for (const key of keys) {
    const pair = optimize[key];
    assert.ok(pair, key);
    assert.ok(pair[0] && pair[1] && pair[0] !== pair[1], key);
  }
});
