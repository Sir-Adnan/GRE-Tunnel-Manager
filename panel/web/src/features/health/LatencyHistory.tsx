import { lazy, Suspense, useContext, useState } from "react";
import { Segmented } from "@/components/Segmented";
import { Skeleton } from "@/components/ui/skeleton";
import { useLoaded } from "@/features/operations/hooks";
import { LocaleContext, useT } from "@/lib/i18n";
import { milliseconds, percent } from "./format";
import {
  latencyPath,
  latencyRanges,
  latencyRefresh,
  latencyRows,
} from "./latency";
import type { LatencyHistory as History, LatencyRange } from "./latency";

const LatencyChart = lazy(() => import("./LatencyChart"));

/** Latency and loss of one monitored connection over a chosen range. */
export function LatencyHistory({
  owner,
  timezone,
}: {
  owner: string;
  timezone?: string;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [range, setRange] = useState<LatencyRange>("24h");
  const history = useLoaded<History>(latencyPath(owner, range), () =>
    latencyRefresh(range),
  );
  // A previous range stays on screen until the new one arrives.
  const value = history.value?.owner === owner ? history.value : undefined;
  const loading = !value || value.range !== range;
  const summary = value?.summary;
  const stats = [
    ["latMean", milliseconds(summary?.mean_ms, locale)],
    ["latPeak", milliseconds(summary?.max_ms, locale)],
    ["latJitter", milliseconds(summary?.jitter_ms, locale)],
    ["latLoss", percent(summary?.loss, locale)],
  ] as const;
  return (
    <section className="latency-history" aria-busy={loading}>
      <header>
        <div className="flex min-w-0 flex-col gap-0.5">
          <h4>{t("latTitle")}</h4>
          <p>{t("latHelp")}</p>
        </div>
        <Segmented
          label={t("latRange")}
          value={range}
          options={latencyRanges.map((value) => ({
            value,
            label: t(`latRange_${value}`),
          }))}
          onChange={(next) => setRange(next as LatencyRange)}
        />
      </header>
      {history.error && !value ? (
        <p className="latency-empty" role="alert">
          {history.error}
        </p>
      ) : (
        <>
          <dl className="latency-stats" data-loading={loading || undefined}>
            {stats.map(([key, text]) => (
              <div key={key}>
                <dt>{t(key)}</dt>
                <dd>
                  <bdi dir="ltr">{value ? text : "—"}</bdi>
                </dd>
              </div>
            ))}
          </dl>
          {value && value.summary.checks === 0 ? (
            <p className="latency-empty">{t("latEmpty")}</p>
          ) : value ? (
            <Suspense fallback={<Skeleton className="latency-chart" />}>
              <LatencyChart
                rows={latencyRows(value)}
                range={value.range}
                timezone={timezone}
              />
            </Suspense>
          ) : (
            <Skeleton className="latency-chart" />
          )}
        </>
      )}
    </section>
  );
}
