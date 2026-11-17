// The Status tab: a filter (all / problems / healthy) with counts and a
// search, then the rows with problems first. Filtering is view-only.
import { useContext, useState } from "react";
import { CheckCircle2, Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Segmented } from "@/components/Segmented";
import { number } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import type { HealthOwner } from "@/features/operations/types";
import { OwnerList } from "./OwnerList";
import {
  filterOwners,
  healthCounts,
  healthFilters,
  type HealthFilter,
} from "./filter";

const labels: Record<HealthFilter, string> = {
  all: "healthFilterAll",
  problems: "healthFilterProblems",
  up: "healthFilterUp",
};

export function StatusList({
  owners,
  ...rest
}: { owners: HealthOwner[] } & Omit<
  Parameters<typeof OwnerList>[0],
  "owners"
>) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const counts = healthCounts(owners);
  const [filter, setFilter] = useState<HealthFilter>("all");
  const [query, setQuery] = useState("");
  const shown = filterOwners(owners, filter, query);
  return (
    <div className="flex flex-col gap-3">
      <div className="health-toolbar">
        <Segmented
          label={t("healthFilterLabel")}
          value={filter}
          onChange={(value) => setFilter(value as HealthFilter)}
          options={healthFilters.map((value) => ({
            value,
            label: t(labels[value]),
            count: number(counts[value], locale),
          }))}
        />
        {counts.problems === 0 && counts.up > 0 && (
          <span className="health-all-clear">
            <CheckCircle2 aria-hidden />
            {t("healthAllClear")}
          </span>
        )}
        {owners.length > 5 && (
          <div className="connection-search health-search">
            <Search className="pointer-events-none absolute start-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              aria-label={t("search")}
              placeholder={t("search")}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              className="ps-9"
            />
          </div>
        )}
      </div>
      {shown.length ? (
        <OwnerList owners={shown} {...rest} />
      ) : (
        <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
          {t("healthFilterEmpty")}
        </p>
      )}
    </div>
  );
}
