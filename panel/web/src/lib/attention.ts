// Derives the overview's "needs attention" list from inventory alone, so it needs no extra privileged call.

/** systemd states that mean an enabled service is not doing its job. */
const problemStates = new Set(["failed", "inactive", "deactivating"]);

export type AttentionItem = {
  kind: "connection" | "resource" | "engine";
  id: string;
  name: string;
  /** systemd state for services; the missing engine for "engine" items. */
  detail: string;
};

type Inputs = {
  connections: {
    id: string;
    name: string;
    engine: string;
    enabled: boolean;
    status?: string;
  }[];
  resources: {
    id: string;
    name: string;
    status: string;
    configured: boolean;
  }[];
  components: { id: string; installed: boolean }[];
};

export function attentionItems({
  connections,
  resources,
  components,
}: Inputs): AttentionItem[] {
  const items: AttentionItem[] = [];
  for (const c of connections)
    if (c.enabled && c.status && problemStates.has(c.status))
      items.push({
        kind: "connection",
        id: c.id,
        name: c.name,
        detail: c.status,
      });
  for (const r of resources)
    if (r.configured && problemStates.has(r.status))
      items.push({
        kind: "resource",
        id: r.id,
        name: r.name,
        detail: r.status,
      });
  // A userspace engine that enabled connections rely on but that is not installed.
  const missing = new Set(
    components.filter((c) => !c.installed).map((c) => c.id),
  );
  for (const engine of new Set(
    connections.filter((c) => c.enabled).map((c) => c.engine),
  ))
    if (missing.has(engine))
      items.push({ kind: "engine", id: engine, name: engine, detail: engine });
  return items;
}
