import { portIn } from "./ports.ts";

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
  resolved?: { ip: string }[];
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
  // A port number also finds the ranges that contain it.
  const port = /^\d{1,5}$/.test(needle) ? Number(needle) : 0;
  return rows.filter(
    (row) =>
      matchesEngine(row.engine, engine) &&
      (status === "all" || connectionStatus(row) === status) &&
      (!needle ||
        (port > 0 && portIn(row.ports, port)) ||
        `${row.name} ${row.id} ${row.engine} ${row.ports} ${[...row.targets, ...(row.resolved || [])].map((target) => target.ip).join(" ")}`
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

/** How the Connections page orders its rows; "custom" is the saved drag order. */
export const connectionSorts = ["custom", "name", "status", "engine"] as const;
export type ConnectionSort = (typeof connectionSorts)[number];
export function connectionSort(value: string | null): ConnectionSort {
  return connectionSorts.includes(value as ConnectionSort)
    ? (value as ConnectionSort)
    : "custom";
}

// Problems first, then running, waiting and switched-off rows.
const statusRank = (row: Pick<Listable, "status" | "enabled">) =>
  ({ active: 1, configured: 2, disabled: 3 })[connectionStatus(row)] ?? 0;

/**
 * Sorts rows that are already in the saved order; ties keep that order, so a
 * sort only groups and never loses the custom order.
 */
export function sortConnections<T extends Listable>(
  rows: readonly T[],
  sort: ConnectionSort,
  locale = "en",
): T[] {
  if (sort === "custom") return [...rows];
  const collator = new Intl.Collator(locale, { numeric: true, sensitivity: "base" });
  const compare: (a: T, b: T) => number =
    sort === "name"
      ? (a, b) => collator.compare(a.name || a.id, b.name || b.id)
      : sort === "status"
        ? (a, b) => statusRank(a) - statusRank(b)
        : (a, b) => collator.compare(a.engine, b.engine);
  return [...rows].sort(compare);
}
