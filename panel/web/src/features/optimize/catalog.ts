// Pure helpers for the Optimization page (no runtime imports; unit-tested).
import type { Inventory } from "@/lib/api";
import type { HealthView } from "@/features/operations/types";
import type {
  OptimizeChange,
  OptimizeGoal,
  OptimizeGroup,
  OptimizeKey,
  OptimizeLevel,
  OptimizeProfile,
  OptimizeView,
} from "./types";

export const groups: OptimizeGroup[] = [
  "conntrack",
  "queues",
  "relay",
  "routing",
];

export const levels: OptimizeLevel[] = [
  "conservative",
  "balanced",
  "aggressive",
];
export const goals: OptimizeGoal[] = ["general", "users", "latency"];

export function sameProfile(a: OptimizeProfile, b: OptimizeProfile): boolean {
  return a.level === b.level && a.goal === b.goal;
}

/** Short, human names for sysctl keys; the full key is shown beside them. */
export const keyLabel: Record<string, string> = {
  "net.netfilter.nf_conntrack_max": "optKeyFlowLimit",
  "net.netfilter.nf_conntrack_buckets": "optKeyBuckets",
  "net.netfilter.nf_conntrack_tcp_timeout_established": "optKeyIdleTcp",
  "net.netfilter.nf_conntrack_tcp_timeout_time_wait": "optKeyTimeWait",
  "net.netfilter.nf_conntrack_tcp_timeout_fin_wait": "optKeyFinWait",
  "net.netfilter.nf_conntrack_tcp_timeout_close_wait": "optKeyCloseWait",
  "net.netfilter.nf_conntrack_udp_timeout": "optKeyUdp",
  "net.netfilter.nf_conntrack_udp_timeout_stream": "optKeyUdpStream",
  "net.core.netdev_max_backlog": "optKeyBacklog",
  "net.core.netdev_budget": "optKeyBudget",
  "net.core.netdev_budget_usecs": "optKeyBudgetTime",
  "net.core.somaxconn": "optKeyAcceptQueue",
  "net.ipv4.tcp_max_syn_backlog": "optKeySynQueue",
  "net.core.default_qdisc": "optKeyQdisc",
  "net.ipv4.tcp_congestion_control": "optKeyCongestion",
  "net.core.rmem_max": "optKeyRmemMax",
  "net.core.wmem_max": "optKeyWmemMax",
  "net.ipv4.tcp_rmem": "optKeyTcpRmem",
  "net.ipv4.tcp_wmem": "optKeyTcpWmem",
  "net.ipv4.tcp_notsent_lowat": "optKeyNotsent",
  "net.ipv4.tcp_mtu_probing": "optKeyMtuProbing",
  "net.ipv4.tcp_slow_start_after_idle": "optKeySlowStart",
  "net.ipv4.tcp_keepalive_time": "optKeyKeepalive",
  "net.ipv4.tcp_keepalive_intvl": "optKeyKeepaliveInterval",
  "net.ipv4.tcp_keepalive_probes": "optKeyKeepaliveProbes",
  "net.ipv4.tcp_fin_timeout": "optKeyFinTimeout",
  "net.ipv4.tcp_tw_reuse": "optKeyTwReuse",
  "net.ipv4.ip_local_port_range": "optKeyPortRange",
  "net.ipv4.tcp_max_tw_buckets": "optKeyTwBuckets",
  "net.ipv4.conf.all.rp_filter": "optKeyRpFilterAll",
  "net.ipv4.conf.default.rp_filter": "optKeyRpFilterDefault",
  "net.ipv4.conf.all.send_redirects": "optKeySendRedirectsAll",
  "net.ipv4.conf.default.send_redirects": "optKeySendRedirectsDefault",
  "net.ipv4.conf.all.accept_redirects": "optKeyAcceptRedirectsAll",
  "net.ipv4.conf.default.accept_redirects": "optKeyAcceptRedirectsDefault",
};

/** Keys whose values are seconds, shown as durations. */
export const secondsKeys = new Set([
  "net.netfilter.nf_conntrack_tcp_timeout_established",
  "net.netfilter.nf_conntrack_tcp_timeout_time_wait",
  "net.netfilter.nf_conntrack_tcp_timeout_fin_wait",
  "net.netfilter.nf_conntrack_tcp_timeout_close_wait",
  "net.netfilter.nf_conntrack_udp_timeout",
  "net.netfilter.nf_conntrack_udp_timeout_stream",
  "net.ipv4.tcp_keepalive_time",
  "net.ipv4.tcp_keepalive_intvl",
  "net.ipv4.tcp_fin_timeout",
]);

/** Keys whose values are byte sizes (single values or min/default/max triples). */
export const byteKeys = new Set([
  "net.core.rmem_max",
  "net.core.wmem_max",
  "net.ipv4.tcp_rmem",
  "net.ipv4.tcp_wmem",
  "net.ipv4.tcp_notsent_lowat",
]);

/** Values that are names of states rather than numbers. */
const stateKeys: Record<string, Record<string, string>> = {
  "net.ipv4.conf.all.rp_filter": { "0": "off", "1": "strict", "2": "loose" },
  "net.ipv4.conf.default.rp_filter": {
    "0": "off",
    "1": "strict",
    "2": "loose",
  },
  "net.ipv4.tcp_tw_reuse": { "0": "off", "1": "on", "2": "loopback" },
  "net.ipv4.tcp_mtu_probing": { "0": "off", "1": "on", "2": "always" },
  "net.ipv4.tcp_slow_start_after_idle": { "0": "off", "1": "on" },
  "net.ipv4.conf.all.send_redirects": { "0": "off", "1": "on" },
  "net.ipv4.conf.default.send_redirects": { "0": "off", "1": "on" },
  "net.ipv4.conf.all.accept_redirects": { "0": "off", "1": "on" },
  "net.ipv4.conf.default.accept_redirects": { "0": "off", "1": "on" },
};

export type GroupState = {
  group: OptimizeGroup;
  keys: OptimizeKey[];
  /** Keys the panel currently manages in this group. */
  applied: number;
  /** Managed keys whose live value differs from what the panel applied. */
  drifted: number;
  /** Keys the recommendation would still change. */
  pending: number;
  /** Keys whose server value is already better than the recommendation. */
  kept: number;
  status: "applied" | "partial" | "available" | "current";
};

export function groupStates(view: OptimizeView): GroupState[] {
  return groups.map((group) => {
    const keys = view.keys.filter((k) => k.group === group);
    const managed = keys.filter((k) => k.applied !== undefined);
    const pending = keys.filter((k) => k.note === "change").length;
    const status: GroupState["status"] = managed.length
      ? pending
        ? "partial"
        : "applied"
      : pending
        ? "available"
        : "current";
    return {
      group,
      keys,
      applied: managed.length,
      drifted: managed.filter((k) => k.current !== k.applied).length,
      pending,
      kept: keys.filter((k) => k.note === "kept").length,
      status,
    };
  });
}

/**
 * Groups that fit what this server runs: kernel forwards need connection
 * tracking, relays need relay TCP, GRE or several addresses need loose
 * reverse-path filtering, and a busy table needs bigger packet queues.
 */
export function serverFit(
  inventory: Pick<Inventory, "connections" | "resources" | "host">,
  view: OptimizeView,
): Set<OptimizeGroup> {
  const fit = new Set<OptimizeGroup>();
  const enabled = inventory.connections.filter((c) => c.enabled);
  if (enabled.some((c) => c.engine === "nftables" || c.engine === "iptables"))
    fit.add("conntrack");
  if (
    enabled.some((c) => c.engine === "haproxy" || c.engine === "realm") ||
    inventory.resources.some(
      (r) => r.engine === "frp" || r.engine === "rathole",
    )
  )
    fit.add("relay");
  const ipv4 = inventory.host.addresses.filter((a) => !a.includes(":"));
  if (inventory.resources.some((r) => r.engine === "gre") || ipv4.length > 1)
    fit.add("routing");
  if ((view.flows ?? 0) >= 20000) fit.add("queues");
  return fit;
}

/** Groups to offer in "Review recommendations": fitting groups with changes. */
export function recommendedGroups(
  states: GroupState[],
  fit: Set<OptimizeGroup>,
): OptimizeGroup[] {
  return states
    .filter((s) => fit.has(s.group) && s.pending > 0)
    .map((s) => s.group);
}

/** Managed keys of any group (including imported ones) for the reset preview. */
export function managedKeys(view: OptimizeView): OptimizeKey[] {
  return view.keys.filter((k) => k.applied !== undefined);
}

/** Memory a full flow table can use: about 350 bytes per flow, 8 per bucket. */
export function flowTableBytes(maxFlows: number, buckets: number): number {
  return maxFlows * 350 + buckets * 8;
}

/** Rows the apply would write: recommendations and custom values. */
export function pendingChanges(changes: OptimizeChange[]): OptimizeChange[] {
  return changes.filter(
    (c) => c.note === "change" || c.note === "custom" || c.note === "worse",
  );
}

/**
 * Checks a custom value against the bounds the server sent (Bash checks it
 * again): numbers in range; triples ascending; ranges low below high; choices.
 */
export function customValid(change: OptimizeChange, value: string): boolean {
  if (change.kind === "choice") return change.choices?.includes(value) ?? false;
  const fields = value.trim().split(/\s+/);
  const count = { number: 1, range: 2, triple: 3 }[change.kind ?? "number"];
  if (!change.kind || fields.length !== count) return false;
  let previous = -1;
  for (const field of fields) {
    if (!/^\d{1,10}$/.test(field)) return false;
    const n = Number(field);
    if (n < (change.min ?? 0) || n > (change.max ?? Infinity)) return false;
    if (n < previous || (change.kind === "range" && n === previous))
      return false;
    previous = n;
  }
  return true;
}

/**
 * Outages that began after the last optimization step, while it is recent
 * (one day): a hint to undo it if tunnels were fine before.
 */
export function outagesSinceApply(
  view: Pick<OptimizeView, "last" | "steps">,
  health: Pick<HealthView, "settings" | "outages"> | undefined,
  now: number,
): HealthView["outages"] {
  if (!view.last || !view.steps || !health?.settings.enabled) return [];
  const applied = view.last * 1000;
  if (now - applied > 86400000) return [];
  return health.outages.filter((o) => Date.parse(o.start) >= applied);
}

function bytes(value: number): string {
  if (value >= 1048576) return `${Math.round((value / 1048576) * 10) / 10} MiB`;
  return value >= 1024 ? `${Math.round(value / 1024)} KiB` : `${value} B`;
}

/** Short value for display: seconds as d/h/m/s, bytes as KiB/MiB, states by name. */
export function compactValue(key: string, value?: string): string {
  if (value === undefined || value === "") return "—";
  if (key === "net.ipv4.ip_local_port_range") return value.replace(" ", "–");
  const state = stateKeys[key]?.[value];
  if (state) return state;
  if (secondsKeys.has(key) && /^\d+$/.test(value)) {
    let rest = Number(value);
    const parts: string[] = [];
    for (const [unit, size] of [
      ["d", 86400],
      ["h", 3600],
      ["m", 60],
    ] as const) {
      if (rest >= size) {
        parts.push(`${Math.floor(rest / size)}${unit}`);
        rest %= size;
      }
    }
    if (rest || !parts.length) parts.push(`${rest}s`);
    return parts.slice(0, 2).join(" ");
  }
  if (byteKeys.has(key) && /^\d+( \d+ \d+)?$/.test(value)) {
    const fields = value.split(" ").map(Number);
    // The kernel default for notsent_lowat (2^32 - 1) means "no limit".
    if (fields.length === 1 && fields[0] >= 4294967295) return "∞";
    return fields.map(bytes).join(" · ");
  }
  return value;
}
