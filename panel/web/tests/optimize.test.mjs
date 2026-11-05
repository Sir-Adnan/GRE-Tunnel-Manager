import test from "node:test";
import assert from "node:assert/strict";
import {
  compactValue,
  flowTableBytes,
  groupStates,
  groups,
  keyLabel,
  managedKeys,
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
  ];
  const keys = [
    ...groups.flatMap((g) => [
      `optGroup_${g}`,
      `optGroupWhy_${g}`,
      `optGroupFor_${g}`,
    ]),
    ...Object.values(keyLabel),
    ...reasons.map((r) => `optWhy_${r}`),
  ];
  for (const key of keys) {
    const pair = optimize[key];
    assert.ok(pair, key);
    assert.ok(pair[0] && pair[1] && pair[0] !== pair[1], key);
  }
});
