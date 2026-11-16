// Ready starting points for a new connection. A template fills the engine,
// protocol, ports and destination shape; the person still enters the
// foreign server and can change anything. Unit-tested in tests/check.test.mjs.
import type { Connection, Inventory } from "./api";

export const templateIDs = ["vpn", "web", "range", "balance", "gre"] as const;
export type TemplateID = (typeof templateIDs)[number];

export type TemplateDraft = Pick<
  Connection,
  "engine" | "protocol" | "ports" | "strategy" | "targets"
> & { port_mode: "" | "same" };

/** Kernel templates prefer nftables, then iptables, then the Realm relay (it also carries UDP). */
function kernelEngine(installed: Set<string>, allowed?: string[]) {
  return (
    ["nftables", "iptables", "realm"].find(
      (e) => installed.has(e) && (!allowed || allowed.includes(e)),
    ) ??
    allowed?.find((e) => ["nftables", "iptables", "realm"].includes(e)) ??
    "nftables"
  );
}

/** GRE tunnels' far-end inner addresses: destinations reached through the tunnel. */
export function grePeers(inventory: Inventory) {
  return inventory.resources
    .filter((r) => r.engine === "gre" && r.peer)
    .map((r) => ({ id: r.id, name: r.name, peer: r.peer as string }));
}

/** Templates that fit: GRE only with a tunnel, and only engines the form may use. */
export function availableTemplates(
  inventory: Inventory,
  allowed?: string[],
): TemplateID[] {
  return templateIDs.filter((id) => {
    if (id === "gre" && grePeers(inventory).length === 0) return false;
    if (!allowed) return true;
    const relay = id === "web" || id === "balance";
    return relay
      ? allowed.includes("haproxy")
      : allowed.some((e) => ["nftables", "iptables", "realm"].includes(e));
  });
}

export function templateDraft(
  id: TemplateID,
  inventory: Inventory,
  allowed?: string[],
): TemplateDraft {
  const installed = new Set(
    inventory.components.filter((c) => c.installed).map((c) => c.id),
  );
  const kernel = kernelEngine(installed, allowed);
  const target = (port: number) => ({ ip: "", port, weight: 1 });
  switch (id) {
    case "vpn":
      return {
        engine: kernel,
        protocol: "both",
        ports: "443",
        port_mode: "",
        strategy: "single",
        targets: [target(443)],
      };
    case "web":
      return {
        engine: "haproxy",
        protocol: "tcp",
        ports: "443",
        port_mode: "",
        strategy: "single",
        targets: [target(443)],
      };
    case "range":
      return {
        engine: kernel,
        protocol: "both",
        ports: "2000-2100",
        port_mode: "same",
        strategy: "single",
        targets: [target(2000)],
      };
    case "balance":
      return {
        engine: "haproxy",
        protocol: "tcp",
        ports: "443",
        port_mode: "",
        strategy: "leastconn",
        targets: [target(443), target(443)],
      };
    case "gre":
      return {
        engine: kernel,
        protocol: "both",
        ports: "443",
        port_mode: "",
        strategy: "single",
        targets: [{ ...target(443), ip: grePeers(inventory)[0]?.peer ?? "" }],
      };
  }
}
