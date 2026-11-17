// Health list filter: which rows to show and in what order. Problems come
// first so a broken tunnel is never below the fold of a long healthy list.
import type { HealthOwner, HealthStatus } from "../operations/types.ts";

export const healthFilters = ["all", "problems", "up"] as const;
export type HealthFilter = (typeof healthFilters)[number];

const rank: Record<HealthStatus, number> = {
  down: 0,
  degraded: 1,
  unknown: 2,
  up: 3,
};

export function isProblem(owner: Pick<HealthOwner, "status">): boolean {
  return owner.status === "down" || owner.status === "degraded";
}

export function healthCounts(owners: readonly HealthOwner[]) {
  const problems = owners.filter(isProblem).length;
  return {
    all: owners.length,
    problems,
    up: owners.filter((o) => o.status === "up").length,
  } satisfies Record<HealthFilter, number>;
}

/** Rows for a filter and search text, worst state first, then by name. */
export function filterOwners(
  owners: readonly HealthOwner[],
  filter: HealthFilter,
  query = "",
): HealthOwner[] {
  const q = query.trim().toLowerCase();
  return owners
    .filter((o) =>
      filter === "problems"
        ? isProblem(o)
        : filter === "up"
          ? o.status === "up"
          : true,
    )
    .filter(
      (o) =>
        !q ||
        o.name.toLowerCase().includes(q) ||
        o.owner.toLowerCase().includes(q) ||
        o.targets.some((x) => (x.address ?? x.unit ?? "").includes(q)),
    )
    .sort(
      (a, b) => rank[a.status] - rank[b.status] || a.name.localeCompare(b.name),
    );
}
