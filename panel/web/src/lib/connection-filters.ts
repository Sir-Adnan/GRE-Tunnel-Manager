// Connection list filters shared by the Connections page, the overview and the command palette.
// Framework-free; the filtered list is only ever a view and is never what a mutation saves.

export const engineFilters = ["all", "kernel", "haproxy", "realm"] as const;
export type EngineFilter = (typeof engineFilters)[number];
export const statusFilters = [
  "all",
  "active",
  "configured",
  "disabled",
] as const;
export type StatusFilter = (typeof statusFilters)[number];

type Listable = {
  id: string;
  name: string;
  engine: string;
  ports: string;
  enabled: boolean;
  status?: string;
  targets: { ip: string }[];
};

export const kernelEngines = ["nftables", "iptables"];

export function engineFilter(value: string | null): EngineFilter {
  return engineFilters.includes(value as EngineFilter)
    ? (value as EngineFilter)
    : "all";
}
export function statusFilter(value: string | null): StatusFilter {
  return statusFilters.includes(value as StatusFilter)
    ? (value as StatusFilter)
    : "all";
}

export function matchesEngine(engine: string, filter: EngineFilter) {
  if (filter === "all") return true;
  if (filter === "kernel") return kernelEngines.includes(engine);
  return engine === filter;
}

/** The status a row shows: the live service state, else what its saved record implies. */
export function connectionStatus(row: Pick<Listable, "status" | "enabled">) {
  return row.status || (row.enabled ? "configured" : "disabled");
}

export function filterConnections<T extends Listable>(
  rows: readonly T[],
  {
    engine = "all",
    status = "all",
    query = "",
  }: { engine?: EngineFilter; status?: StatusFilter; query?: string },
): T[] {
  const needle = query.trim().toLowerCase();
  return rows.filter(
    (row) =>
      matchesEngine(row.engine, engine) &&
      (status === "all" || connectionStatus(row) === status) &&
      (!needle ||
        `${row.name} ${row.id} ${row.engine} ${row.ports} ${row.targets.map((target) => target.ip).join(" ")}`
          .toLowerCase()
          .includes(needle)),
  );
}

/** Number of rows per engine filter, for the filter chips. */
export function engineCounts(rows: readonly Pick<Listable, "engine">[]) {
  return Object.fromEntries(
    engineFilters.map((filter) => [
      filter,
      rows.filter((row) => matchesEngine(row.engine, filter)).length,
    ]),
  ) as Record<EngineFilter, number>;
}

/** The engine a new connection starts with when created from a filtered view. */
export function creationEngine(filter: EngineFilter) {
  return filter === "kernel"
    ? "nftables"
    : filter === "realm"
      ? "realm"
      : "haproxy";
}
/** Engines the creation form may offer from a filtered view; undefined offers all. */
export function creationEngines(filter: EngineFilter) {
  return filter === "kernel"
    ? kernelEngines
    : filter === "all"
      ? undefined
      : [filter];
}
