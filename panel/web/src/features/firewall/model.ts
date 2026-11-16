// Firewall page model: the report from GET /api/firewall, the editable
// settings and the pure rules that turn them into findings and summaries.
// No React here, so the rules are unit-tested (tests/firewall.test.mjs).

export type AccessMode = "off" | "allow" | "deny";
export type FirewallAccess = {
  id: string;
  mode: AccessMode;
  sources: string[];
  per_ip: number;
  rate: number;
};
export type FirewallSettings = {
  private_ranges: boolean;
  smtp: boolean;
  exceptions: string[];
  access: FirewallAccess[];
  ufw: string[];
};
export type FirewallBackend = {
  family: 4 | 6;
  tool: string;
  kind: "nf_tables" | "legacy";
  input: string;
  forward: string;
  guard: boolean;
};
export type FirewallPort = {
  id: string;
  protocol: "tcp" | "udp";
  port: string;
  ufw: "" | "tagged" | "open" | "closed";
};
export type FirewallStatus = {
  revision: string;
  nft: boolean;
  applied?: boolean;
  pending?: string;
  ufw: {
    state: "missing" | "inactive" | "active";
    incoming: string;
    routed: string;
  };
  firewalld?: "active" | "inactive";
  docker: boolean;
  backends: FirewallBackend[];
  tables: string[];
  uplinks: string[];
  ssh: number[];
  auto_exceptions: string[];
  ports: FirewallPort[];
  counters: { rule: string; packets: number; bytes: number }[];
  settings: FirewallSettings;
};
/** The fields of a connection the firewall page needs. */
export type FirewallConnection = {
  id: string;
  name: string;
  engine: string;
  protocol: string;
  bind: string;
  ports: string;
  enabled: boolean;
};

export const kernelEngine = (engine: string) =>
  engine === "nftables" || engine === "iptables";
export const familyOf = (bind: string): 4 | 6 => (bind.includes(":") ? 6 : 4);

export type Finding = {
  id: string;
  level: "problem" | "warn";
  key: string;
  vars: Record<string, string>;
  fix?: "repair" | "ufw";
  connection?: string;
};

/** What blocks or may block traffic, most severe first. */
export function findings(
  status: FirewallStatus,
  connections: FirewallConnection[],
): Finding[] {
  const out: Finding[] = [];
  const active = connections.filter((c) => c.enabled);
  for (const b of status.backends) {
    const used = active.some(
      (c) => kernelEngine(c.engine) && familyOf(c.bind) === b.family,
    );
    if (used && b.forward === "DROP" && !b.guard)
      out.push({
        id: `guard-${b.tool}`,
        level: "problem",
        key: "fwGuardMissing",
        vars: { tool: b.tool, f: String(b.family) },
        fix: "repair",
      });
  }
  if (status.applied === false)
    out.push({
      id: "applied",
      level: "problem",
      key: "fwNotApplied",
      vars: {},
      fix: "repair",
    });
  if (!status.nft && wantsRules(status.settings))
    out.push({ id: "nft", level: "problem", key: "fwNoNft", vars: {} });
  if (status.ufw.state === "active" && status.ufw.incoming !== "allow") {
    const byID = new Map(active.map((c) => [c.id, c]));
    const seen = new Set<string>();
    for (const p of status.ports) {
      const c = byID.get(p.id);
      if (!c || kernelEngine(c.engine) || p.ufw !== "closed" || seen.has(c.id))
        continue;
      seen.add(c.id);
      out.push({
        id: `ufw-${c.id}`,
        level: "warn",
        key: "fwRelayClosed",
        vars: { p: `${p.port}/${p.protocol}`, n: c.name || c.id },
        fix: "ufw",
        connection: c.id,
      });
    }
  }
  if (status.firewalld === "active")
    out.push({ id: "firewalld", level: "warn", key: "fwFirewalld", vars: {} });
  return out;
}

export function wantsRules(s: FirewallSettings) {
  return (
    s.private_ranges ||
    s.smtp ||
    s.access.some((a) => a.mode !== "off" || a.per_ip > 0 || a.rate > 0)
  );
}

export const emptyAccess = (id: string): FirewallAccess => ({
  id,
  mode: "off",
  sources: [],
  per_ip: 0,
  rate: 0,
});

export function accessOf(s: FirewallSettings, id: string): FirewallAccess {
  return s.access.find((a) => a.id === id) ?? emptyAccess(id);
}

/** Replaces one connection's access; an entry without any rule is dropped. */
export function withAccess(
  s: FirewallSettings,
  next: FirewallAccess,
): FirewallSettings {
  const rest = s.access.filter((a) => a.id !== next.id);
  const empty = next.mode === "off" && next.per_ip === 0 && next.rate === 0;
  return {
    ...s,
    access: empty
      ? rest
      : [
          ...rest,
          { ...next, sources: next.mode === "off" ? [] : next.sources },
        ],
  };
}

export function withUFW(
  s: FirewallSettings,
  id: string,
  open: boolean,
): FirewallSettings {
  const rest = s.ufw.filter((x) => x !== id);
  return { ...s, ufw: open ? [...rest, id] : rest };
}

/** Settings compared by meaning (order of entries does not matter). */
export function sameSettings(a: FirewallSettings, b: FirewallSettings) {
  const key = (s: FirewallSettings) =>
    JSON.stringify({
      p: s.private_ranges,
      m: s.smtp,
      e: [...s.exceptions].sort(),
      u: [...s.ufw].sort(),
      a: [...s.access]
        .filter((x) => x.mode !== "off" || x.per_ip > 0 || x.rate > 0)
        .map((x) => ({
          ...x,
          sources: x.mode === "off" ? [] : [...x.sources].sort(),
        }))
        .sort((x, y) => x.id.localeCompare(y.id)),
    });
  return key(a) === key(b);
}

const v4 =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const v6 = /^[0-9a-f:]+$/i;

/** Client-side check of one address or network; the server canonicalizes. */
export function sourceFamily(value: string): 4 | 6 | undefined {
  const [address, bits, extra] = value.split("/");
  if (extra !== undefined) return undefined;
  if (v4.test(address)) {
    if (address === "0.0.0.0") return undefined;
    if (bits === undefined) return 4;
    return /^\d+$/.test(bits) && +bits >= 1 && +bits <= 32 ? 4 : undefined;
  }
  if (
    v6.test(address) &&
    address.includes(":") &&
    (address.match(/::/g) ?? []).length <= 1
  ) {
    if (address === "::") return undefined;
    if (bits === undefined) return 6;
    return /^\d+$/.test(bits) && +bits >= 1 && +bits <= 128 ? 6 : undefined;
  }
  return undefined;
}

export function parseSources(text: string) {
  const sources: string[] = [];
  const invalid: string[] = [];
  for (const word of text.split(/[\s,]+/).filter(Boolean)) {
    if (!sourceFamily(word)) invalid.push(word);
    else if (!sources.includes(word)) sources.push(word);
  }
  return { sources, invalid };
}

/** The first problem with one connection's access, as a message key. */
export function accessProblem(
  access: FirewallAccess,
  bind: string,
): { key: string; vars: Record<string, string> } | undefined {
  if (access.mode === "off") return undefined;
  if (access.sources.length === 0) return { key: "fwSourcesNeeded", vars: {} };
  const family = familyOf(bind);
  if (
    access.mode === "allow" &&
    !access.sources.some((s) => sourceFamily(s) === family)
  )
    return { key: "fwSourcesFamily", vars: { f: String(family) } };
  return undefined;
}

/** Packets the connection's rules dropped (all of its counters). */
export function blockedFor(status: FirewallStatus, id: string) {
  return status.counters
    .filter((c) => c.rule.startsWith(`${id}-`))
    .reduce((sum, c) => sum + c.packets, 0);
}

export function counter(status: FirewallStatus, rule: string) {
  return status.counters.find((c) => c.rule === rule)?.packets ?? 0;
}
