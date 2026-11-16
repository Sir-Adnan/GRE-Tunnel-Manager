// IP tools model: what uses an address, what an IP change touches, which
// tunnel ends another Node can move by itself and how to read the results.
// Pure functions only, so tests run without a browser.

export type Use = "local" | "remote";
export type AddressUse = {
  use: Use;
  address: string;
  kind: "gre" | "connection" | "reverse";
  id: string;
  name: string;
  present: boolean;
  editable: boolean;
};
export type HostAddress = {
  interface: string;
  address: string;
  prefix: number;
  uplink: boolean;
  container: boolean;
};
export type ExtraAddress = {
  id: number;
  address: string;
  interface: string;
  gateway?: string;
  active: boolean;
  present: boolean;
};
export type AddressReport = {
  addresses: HostAddress[];
  uplink: string;
  gateway: string;
  interfaces: string[];
  uses: AddressUse[];
  stale: string[];
  suggested: string;
  extra: ExtraAddress[];
};

/** First Agent release that runs readdress jobs (control.ReaddressVersion). */
export const readdressVersion = "1.6.0";

export const family = (address: string) => (address.includes(":") ? 6 : 4);

const ipv4 =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const ipv6 = /^[0-9a-fA-F:]+$/;

/** A literal address that a tunnel or listener can use (not wildcard, loopback or link-local). */
export function usableAddress(value: string): boolean {
  const v = value.trim();
  if (ipv4.test(v)) return !/^(0|127)\./.test(v) && v !== "255.255.255.255";
  if (!ipv6.test(v) || !v.includes(":") || (v.match(/::/g) ?? []).length > 1)
    return false;
  const lower = v.toLowerCase();
  const groups = lower.split(":").filter(Boolean);
  if (groups.length > 8 || groups.some((g) => g.length > 4)) return false;
  if (!lower.includes("::") && groups.length !== 8) return false;
  return !["::", "::1"].includes(lower) && !/^fe[89ab]/.test(lower);
}

/** Local addresses that saved resources still use but the server no longer has. */
export function staleLocal(inventory: {
  host: { addresses: string[] };
  connections: { bind: string }[];
  resources: { engine: string; bind?: string }[];
}): string[] {
  const present = new Set(inventory.host.addresses);
  const out: string[] = [];
  const binds = [
    ...inventory.connections.map((c) => c.bind),
    ...inventory.resources
      .filter((r) => r.engine === "gre")
      .map((r) => r.bind ?? ""),
  ];
  for (const bind of binds)
    if (usableAddress(bind) && !present.has(bind) && !out.includes(bind))
      out.push(bind);
  return out;
}

/** Addresses that can be the old one, stale local addresses first. */
export function oldChoices(report: AddressReport, use: Use): string[] {
  const out: string[] = use === "local" ? [...report.stale] : [];
  for (const u of report.uses)
    if (u.use === use && !out.includes(u.address)) out.push(u.address);
  return out;
}

/** Server addresses a local use may move to: same family, not the old one, not a container bridge. */
export function newChoices(report: AddressReport, old: string): string[] {
  return report.addresses
    .filter(
      (a) =>
        !a.container && a.address !== old && family(a.address) === family(old),
    )
    .map((a) => a.address);
}

export function usesOf(report: AddressReport, use: Use, old: string) {
  return report.uses.filter((u) => u.use === use && u.address === old);
}

type NodeLike = {
  id: string;
  name: string;
  revision: string;
  local: boolean;
  status: string;
  version?: string;
  capabilities: string[];
  inventory?: {
    host?: { addresses?: string[] };
    resources?: {
      id: string;
      engine: string;
      bind?: string;
      remote?: string;
    }[];
  };
};

export function versionAtLeast(version = "", minimum = readdressVersion) {
  const parse = (v: string) =>
    v
      .split(/[-+]/, 1)[0]
      .split(".")
      .map((p) => (/^\d+$/.test(p) ? Number(p) : NaN));
  const a = parse(version);
  const b = parse(minimum);
  if (a.length !== 3 || a.some(Number.isNaN)) return false;
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] > b[i];
  return true;
}

export type Partner = {
  node: NodeLike;
  /** GRE tunnels that the Node holds the other end of. */
  ids: string[];
  /** Why automatic is unavailable (an older Agent), or "" when ready. */
  blocked: "" | "agentOutdated" | "nodeOffline";
};

/**
 * The remote Node holding the other end of this server's GRE tunnels that use
 * the old address: for a local change its tunnel's remote is the old address,
 * for a remote change (that Node's address changed) its tunnel's local end is.
 * Only one Node is moved automatically; the others get a command.
 */
export function partnerNode(
  nodes: NodeLike[],
  gre: AddressUse[],
  use: Use,
  old: string,
): Partner | undefined {
  const wanted = new Set(gre.filter((u) => u.kind === "gre").map((u) => u.id));
  for (const node of nodes) {
    if (node.local) continue;
    const ids = (node.inventory?.resources ?? [])
      .filter(
        (r) =>
          r.engine === "gre" &&
          wanted.has(r.id) &&
          (use === "local" ? r.remote === old : r.bind === old),
      )
      .map((r) => r.id);
    if (!ids.length) continue;
    const ready =
      node.status === "online" &&
      node.capabilities.includes("connections.pair.v1");
    return {
      node,
      ids,
      blocked: !ready
        ? "nodeOffline"
        : versionAtLeast(node.version)
          ? ""
          : "agentOutdated",
    };
  }
  return undefined;
}

/** Remote ends of local GRE uses that no ready Node moves: each needs the command. */
export function manualPeers(
  gre: AddressUse[],
  remotes: Record<string, string>,
  partner?: Partner,
): string[] {
  const covered = new Set(partner && !partner.blocked ? partner.ids : []);
  const out: string[] = [];
  for (const u of gre) {
    const remote = remotes[u.id];
    if (
      u.kind === "gre" &&
      !covered.has(u.id) &&
      remote &&
      !out.includes(remote)
    )
      out.push(remote);
  }
  return out;
}

/** The engine command that moves the other server's side by hand. */
export function peerCommand(old: string, next: string, use: Use) {
  return `sudo bash gre.sh --api address-replace ${old} ${next || "NEW_IP"} ${use} all`;
}

/** Per-item results of address-replace ("result\tID\tdone|failed"), also inside an error text. */
export function parseResults(text: string): Record<string, "done" | "failed"> {
  const out: Record<string, "done" | "failed"> = {};
  for (const line of text.split(/\r?\n|\\n/)) {
    const m = /result(?:\t|\\t)(\S+)(?:\t|\\t)(done|failed)/.exec(line);
    if (m) out[m[1]] = m[2] as "done" | "failed";
  }
  return out;
}

/** extra-add output: the unit number and the address/route checks. */
export function parseExtraResult(text: string) {
  const id = /extra(?:\t|\\t)(\d+)/.exec(text)?.[1];
  const check = (name: string) =>
    new RegExp(`check(?:\\t|\\\\t)${name}(?:\\t|\\\\t)1`).test(text);
  return {
    id: id ? Number(id) : undefined,
    present: check("present"),
    route: check("route"),
  };
}

/** Validates ADDRESS/PREFIX for an additional address; returns a message key or "". */
export function extraProblem(
  cidr: string,
  gateway: string,
  host: HostAddress[],
) {
  const [address, prefix, rest] = cidr.trim().split("/");
  if (rest !== undefined || !usableAddress(address ?? ""))
    return "ipExtraBadAddress";
  const max = family(address) === 4 ? 32 : 128;
  const bits = prefix === undefined || prefix === "" ? max : Number(prefix);
  if (!Number.isInteger(bits) || bits < 8 || bits > max)
    return "ipExtraBadPrefix";
  if (host.some((h) => h.address === address)) return "ipExtraExists";
  if (
    gateway &&
    (!usableAddress(gateway) || family(gateway) !== family(address))
  )
    return "ipExtraBadGateway";
  return "";
}

/** Adds the host-route prefix when the operator typed a bare address. */
export function withPrefix(cidr: string) {
  const v = cidr.trim();
  return v.includes("/") ? v : `${v}/${family(v) === 4 ? 32 : 128}`;
}
