// Two-server setup: a GRE tunnel from this (entrance) server to a foreign
// server, then a kernel forward of public ports through it. This module holds
// the draft, its checks and the two broker requests; the dialog only renders.
// Framework-free; unit-tested in tests/wizard.test.mjs.
import type { Connection, Inventory } from "../../lib/api";
import { parseSpans } from "../../lib/ports.ts";
import { templateDraft } from "../../lib/templates.ts";

export type Protocol = "tcp" | "udp" | "both";

export type WizardDraft = {
  /** The foreign server's public address. */
  remote: string;
  /** This server's public address (GRE source). */
  bind: string;
  id: number;
  mtu: number;
  /** Public ports on this server, forwarded to the same ports over the tunnel. */
  ports: string;
  protocol: Protocol;
  name: string;
  /** False creates the tunnel only. */
  forward: boolean;
};

export type WizardField = "remote" | "bind" | "id" | "mtu" | "ports" | "name";
/** Message keys by field; empty when the step is complete. */
export type WizardErrors = Partial<Record<WizardField, string>>;

/** The engine's rule for connection names (model.ValidName). */
export const connectionName = /^[A-Za-z0-9 ._-]{1,40}$/;

const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

export function validIP(value: string): boolean {
  if (ipv4.test(value)) return true;
  if (!/^[0-9a-f:]+$/i.test(value) || !value.includes(":")) return false;
  try {
    return new URL(`http://[${value}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

const greIDs = (inventory: Inventory) =>
  new Set(
    inventory.resources
      .filter((r) => r.engine === "gre")
      .map((r) => Number(/^gre-tun-(\d+)$/.exec(r.id)?.[1]))
      .filter(Boolean),
  );

/** The lowest tunnel ID this server does not use yet (1–250). */
export function freeTunnelID(inventory: Inventory): number {
  const used = greIDs(inventory);
  for (let id = 1; id <= 250; id++) if (!used.has(id)) return id;
  return 0;
}

/** Inner addresses: the entrance (Iran / Side B) end and the foreign (Side A) end. */
export function tunnelAddresses(id: number) {
  return { entrance: `10.0.${id}.2`, foreign: `10.0.${id}.1` };
}

/** The largest MTU the far end's address family allows. */
export const maxMTU = (remote: string) => (remote.includes(":") ? 1452 : 1472);

export function wizardDefaults(inventory: Inventory): WizardDraft {
  return {
    remote: "",
    bind: inventory.host.addresses.find((ip) => !ip.includes(":")) ?? "",
    id: freeTunnelID(inventory),
    mtu: 1430,
    ports: "443",
    protocol: "both",
    name: "",
    forward: true,
  };
}

const overlaps = (a: Protocol | string, b: Protocol | string) =>
  a === "both" || b === "both" || a === b;

/** A connection that already listens on one of the ports, for the same protocol. */
export function portOwner(
  draft: Pick<WizardDraft, "ports" | "protocol">,
  inventory: Inventory,
): Connection | undefined {
  const wanted = parseSpans(draft.ports, true).spans;
  return inventory.connections.find(
    (c) =>
      overlaps(c.protocol, draft.protocol) &&
      parseSpans(c.ports, true).spans.some((s) =>
        wanted.some((w) => w.first <= s.last && s.first <= w.last),
      ),
  );
}

/** Checks of step 0 (tunnel) or step 1 (forward). */
export function wizardErrors(
  draft: WizardDraft,
  inventory: Inventory,
  step: 0 | 1,
): WizardErrors {
  const errors: WizardErrors = {};
  if (step === 0) {
    if (!validIP(draft.remote.trim())) errors.remote = "wizErrorAddress";
    else if (draft.remote.trim() === draft.bind.trim())
      errors.remote = "wizErrorSameServer";
    if (!validIP(draft.bind.trim())) errors.bind = "wizErrorAddress";
    else if (
      validIP(draft.remote.trim()) &&
      draft.remote.includes(":") !== draft.bind.includes(":")
    )
      errors.bind = "wizErrorFamily";
    if (!Number.isInteger(draft.id) || draft.id < 1 || draft.id > 250)
      errors.id = "wizErrorID";
    else if (greIDs(inventory).has(draft.id)) errors.id = "wizErrorIDUsed";
    if (
      !Number.isInteger(draft.mtu) ||
      draft.mtu < 1280 ||
      draft.mtu > maxMTU(draft.remote)
    )
      errors.mtu = "wizErrorMTU";
    return errors;
  }
  if (draft.name.trim() && !connectionName.test(draft.name.trim()))
    errors.name = "wizErrorName";
  if (!draft.forward) return errors;
  const parsed = parseSpans(draft.ports, true);
  if (parsed.error) errors.ports = `portsError_${parsed.error}`;
  else if (portOwner(draft, inventory)) errors.ports = "wizErrorPortUsed";
  return errors;
}

/** The GRE request for this server. */
export function greRequest(draft: WizardDraft) {
  return {
    id: draft.id,
    role: "iran",
    remote: draft.remote.trim(),
    bind: draft.bind.trim(),
    mtu: draft.mtu,
  };
}

/** What to enter on the foreign server: the same tunnel with the opposite role. */
export function farSide(draft: WizardDraft) {
  return {
    id: draft.id,
    role: "kharej",
    remote: draft.bind.trim(),
    bind: draft.remote.trim(),
    mtu: draft.mtu,
  };
}

/** The forward through the tunnel: the same port numbers on the foreign end. */
export function forwardConnection(
  draft: WizardDraft,
  inventory: Inventory,
  /** The engine's defaults for a new connection (lib/creation-defaults). */
  options: (engine: string) => Record<string, string>,
): Connection {
  const template = templateDraft("gre", inventory);
  const spans = parseSpans(draft.ports, true).spans;
  const single = spans.length === 1 && spans[0].first === spans[0].last;
  const ports = spans
    .map((s) => (s.first === s.last ? `${s.first}` : `${s.first}-${s.last}`))
    .join(",");
  return {
    id: "",
    revision: "",
    name: draft.name.trim() || defaultName(draft.id, ports),
    engine: template.engine,
    protocol: draft.protocol,
    bind: "0.0.0.0",
    ports,
    strategy: "single",
    enabled: true,
    snat: "masquerade",
    interface: "any",
    port_mode: single ? "" : "same",
    targets: [
      {
        ip: tunnelAddresses(draft.id).foreign,
        port: spans[0]?.first ?? 443,
        weight: 1,
      },
    ],
    options: options(template.engine),
  };
}

/**
 * "GRE 2 443" or "GRE 2 2000-2100" for one port or range. With several, the
 * engine saves one connection per entry and appends "-port" to each name
 * itself ("GRE 2-443"), so the ports are left out here.
 */
export function defaultName(id: number, ports: string): string {
  const spans = ports.split(/[\s,]+/).filter(Boolean);
  return spans.length === 1 ? `GRE ${id} ${spans[0]}` : `GRE ${id}`;
}
