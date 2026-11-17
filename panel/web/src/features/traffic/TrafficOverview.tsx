// The Traffic page's first view: what is moving now (live), who moves it
// (busiest), and how much this cycle (totals and quotas). When usage
// collection is off, one card explains it and turns it on.
import { useContext, useMemo } from "react";
import {
  Activity,
  ArrowDown,
  ArrowUp,
  ChevronLeft,
  ChevronRight,
  Gauge,
  Loader2,
  Sigma,
  Trophy,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { EngineGlyph } from "@/components/shared";
import { HelpTip } from "@/components/help";
import { Sparkline } from "@/components/Sparkline";
import type { Metrics } from "@/lib/api";
import { bitRate, number, trafficBytes } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import { sparkPath, sparkSamples } from "@/lib/sparkline";
import { cycleUsage, quotaUsage } from "./accounting";
import { useBusiest, useLive } from "./use-live";
import type { TrafficResource } from "./resources";

export function TrafficOverview({
  metrics,
  resources,
  busy,
  onEnable,
  onDetails,
}: {
  metrics?: Metrics;
  resources: TrafficResource[];
  busy: boolean;
  onEnable: () => void;
  onDetails: (id: string) => void;
}) {
  if (!metrics) return <Skeleton className="h-56 w-full rounded-xl" />;
  if (!metrics.settings.enabled)
    return <CollectionOff busy={busy} onEnable={onEnable} />;
  return (
    <div className="traffic-overview">
      <LivePanel />
      <Busiest resources={resources} onDetails={onDetails} />
      <CycleSummary metrics={metrics} resources={resources} />
    </div>
  );
}

function CollectionOff({
  busy,
  onEnable,
}: {
  busy: boolean;
  onEnable: () => void;
}) {
  const t = useT();
  return (
    <Card className="traffic-off">
      <CardContent className="flex flex-col items-start gap-4">
        <span className="traffic-off-icon" aria-hidden>
          <Activity />
        </span>
        <div className="flex max-w-xl flex-col gap-1.5">
          <h2 className="text-title font-semibold">{t("liveOffTitle")}</h2>
          <p className="text-sm text-muted-foreground">{t("liveOffBody")}</p>
        </div>
        <Button disabled={busy} onClick={onEnable}>
          {busy ? (
            <Loader2 data-icon="inline-start" className="animate-spin" />
          ) : (
            <Activity data-icon="inline-start" />
          )}
          {t("turnOnCollection")}
        </Button>
      </CardContent>
    </Card>
  );
}

function LivePanel() {
  const t = useT(),
    locale = useContext(LocaleContext);
  const live = useLive();
  const received = live.total.received.at(-1);
  const sent = live.total.sent.at(-1);
  const active = Object.values(live.rates).filter(
    (r) => r.received + r.sent >= 1,
  ).length;
  return (
    <Card className="traffic-live">
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <CardTitle>{t("liveThroughput")}</CardTitle>
            <HelpTip>{t("liveThroughputHelp")}</HelpTip>
          </div>
          <span
            className="traffic-live-state"
            data-ready={live.ready || undefined}
          >
            <span className="live-dot" aria-hidden />
            {live.ready
              ? t("liveActive").replace("{n}", number(active, locale))
              : t("liveMeasuring")}
          </span>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <dl className="traffic-readouts">
          {(
            [
              ["received", ArrowDown, received],
              ["sent", ArrowUp, sent],
            ] as const
          ).map(([key, Icon, value]) => (
            <div key={key} className="traffic-readout" data-dir={key}>
              <dt>
                <Icon aria-hidden />
                {t(key)}
              </dt>
              <dd className="traffic-readout-value">
                <bdi dir="ltr">
                  {bitRate(live.ready ? value : null, locale)}
                </bdi>
              </dd>
              <dd className="traffic-readout-detail">
                <bdi dir="ltr">
                  {live.ready && value != null
                    ? `${trafficBytes(value, locale)}/s`
                    : "—"}
                </bdi>
              </dd>
            </div>
          ))}
        </dl>
        <LiveChart received={live.total.received} sent={live.total.sent} />
      </CardContent>
    </Card>
  );
}

/** Two series over the last minute: received as an area, sent as a line. */
function LiveChart({
  received,
  sent,
}: {
  received: readonly number[];
  sent: readonly number[];
}) {
  const width = 300,
    height = 88;
  const max = Math.max(1, ...received, ...sent) * 1.15;
  const down = sparkPath(received, width, height, max);
  const up = sparkPath(sent, width, height, max);
  const start = width - (width / (sparkSamples - 1)) * (received.length - 1);
  return (
    <div className="traffic-chart" dir="ltr" aria-hidden>
      <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none">
        {[0.25, 0.5, 0.75].map((y) => (
          <line
            key={y}
            className="traffic-chart-grid"
            x1="0"
            x2={width}
            y1={height * y}
            y2={height * y}
          />
        ))}
        {down && (
          <>
            <path
              className="traffic-chart-area"
              d={`${down} L${width} ${height} L${start.toFixed(1)} ${height} Z`}
            />
            <path className="traffic-chart-down" d={down} />
          </>
        )}
        {up && <path className="traffic-chart-up" d={up} />}
      </svg>
    </div>
  );
}

function Busiest({
  resources,
  onDetails,
}: {
  resources: TrafficResource[];
  onDetails: (id: string) => void;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const live = useLive();
  const rows = useBusiest(5);
  const top = rows[0]?.total || 1;
  const Chevron = locale === "fa" ? ChevronLeft : ChevronRight;
  return (
    <Card className="traffic-busiest">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Gauge className="size-4" aria-hidden />
          {t("busiestNow")}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {!live.ready ? (
          <div className="flex flex-col gap-3">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : rows.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">
            {t("busiestEmpty")}
          </p>
        ) : (
          <ol className="traffic-rank">
            {rows.map((r) => {
              const resource = resources.find((x) => x.id === r.id);
              return (
                <li key={r.id}>
                  <button
                    type="button"
                    className="traffic-rank-row"
                    onClick={() => onDetails(r.id)}
                  >
                    <span className="traffic-rank-name">
                      <EngineGlyph
                        engine={resource?.engine || "gre"}
                        className="size-3.5 shrink-0 text-muted-foreground"
                      />
                      <span className="truncate">{resource?.name || r.id}</span>
                    </span>
                    <span className="traffic-rank-rate">
                      <bdi dir="ltr">{bitRate(r.total, locale)}</bdi>
                    </span>
                    <Chevron aria-hidden className="traffic-rank-chevron" />
                    <span className="traffic-rank-bar" aria-hidden>
                      <span
                        style={{ inlineSize: `${(100 * r.total) / top}%` }}
                      />
                    </span>
                    <Sparkline
                      values={live.trends[r.id] ?? []}
                      className="traffic-rank-spark"
                    />
                  </button>
                </li>
              );
            })}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}

function CycleSummary({
  metrics,
  resources,
}: {
  metrics: Metrics;
  resources: TrafficResource[];
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const summary = useMemo(() => {
    let received = 0,
      sent = 0,
      watched = 0,
      top = { id: "", total: 0 };
    let counted = 0,
      tunnels = 0;
    for (const [id, c] of Object.entries(metrics.counters)) {
      const policy = metrics.policies?.[id];
      if (policy?.limit && quotaUsage(c, policy).percent >= 80) watched++;
      // GRE interface counters carry the same bytes as the forwards over
      // them: shown per tunnel, never added to the totals.
      if (c.source === "interface") {
        tunnels++;
        continue;
      }
      counted++;
      const u = cycleUsage(c);
      received += u.received;
      sent += u.sent;
      if (u.received + u.sent > top.total)
        top = { id, total: u.received + u.sent };
    }
    return { received, sent, watched, top, counted, tunnels };
  }, [metrics]);
  const total = summary.received + summary.sent;
  const topName =
    resources.find((r) => r.id === summary.top.id)?.name || summary.top.id;
  const tiles = [
    {
      key: "received",
      icon: ArrowDown,
      value: trafficBytes(summary.received, locale),
      detail: t("cycleTotals"),
    },
    {
      key: "sent",
      icon: ArrowUp,
      value: trafficBytes(summary.sent, locale),
      detail: t("cycleTotals"),
    },
    {
      key: "total",
      icon: Sigma,
      value: trafficBytes(total, locale),
      detail:
        t("trackedCount").replace("{n}", number(summary.counted, locale)) +
        (summary.tunnels
          ? ` · ${t("tunnelsSeparate").replace("{n}", number(summary.tunnels, locale))}`
          : ""),
    },
    {
      key: "topUser",
      icon: Trophy,
      value: summary.top.id ? topName : "—",
      detail: summary.top.id
        ? `${trafficBytes(summary.top.total, locale)} · ${t(
            "shareOfTotal",
          ).replace(
            "{p}",
            `${number(total ? (100 * summary.top.total) / total : 0, locale)}%`,
          )}`
        : summary.watched
          ? t("quotaWatchBody").replace("{n}", number(summary.watched, locale))
          : t("quotaWatchClear"),
      text: true,
    },
  ];
  return (
    <dl className="traffic-tiles">
      {tiles.map(({ key, icon: Icon, value, detail, text }) => (
        <div key={key} className="traffic-tile">
          <dt>
            <Icon aria-hidden />
            {t(key)}
          </dt>
          <dd className="traffic-tile-value" data-text={text || undefined}>
            <bdi dir={text ? "auto" : "ltr"}>{value}</bdi>
          </dd>
          <dd className="traffic-tile-detail">
            <bdi>{detail}</bdi>
          </dd>
        </div>
      ))}
      {summary.watched > 0 && (
        <p className="traffic-tiles-note" role="status">
          {t("quotaWatch")}:{" "}
          {t("quotaWatchBody").replace("{n}", number(summary.watched, locale))}
        </p>
      )}
    </dl>
  );
}
