import type { Inventory } from "@/lib/api";

/** Something usage collection can count: a connection, a GRE tunnel or a reverse tunnel's public port. */
export type TrafficResource = {
  id: string;
  name: string;
  engine: string;
  /** Ports, a port or the GRE interface, for display. */
  port: string;
};

export function trafficResources(inventory: Inventory): TrafficResource[] {
  return [
    ...inventory.connections.map((c) => ({
      id: c.id,
      name: c.name,
      engine: c.engine,
      port: c.ports,
    })),
    ...inventory.resources
      .filter((r) => r.engine === "gre" || (r.role === "entrance" && r.port))
      .map((r) => ({
        id: r.id,
        name: r.name,
        engine: r.engine,
        port: r.port ? String(r.port) : r.interface || "",
      })),
  ];
}
