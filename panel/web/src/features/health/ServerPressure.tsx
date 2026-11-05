import { useContext } from "react";
import {
  Cpu,
  ArrowUpRight,
  Gauge,
  Lightbulb,
  TriangleAlert,
} from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { HelpTip } from "@/components/help";
import { routeURL } from "@/lib/navigation";
import { number } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import type { HostPressure } from "@/features/operations/types";
import { Meter } from "./Indicators";
import { duration } from "./format";

function Row({
  label,
  value,
  text = false,
}: {
  label: string;
  value: string;
  text?: boolean;
}) {
  return (
    <div className="flex items-baseline justify-between gap-3 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="font-medium tabular-nums">
        <bdi dir={text ? undefined : "ltr"}>{value}</bdi>
      </dd>
    </div>
  );
}

/** Conntrack and CPU pressure from /proc, linked to the Optimization page. */
export function ServerPressure({ host }: { host?: HostPressure }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  if (!host)
    return (
      <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
        {t("healthWaiting")}
      </p>
    );
  const pct = (v?: number) => (v == null ? "—" : `${number(v, locale, 1)}%`);
  const n = (v?: number) => (v == null ? "—" : number(v, locale));
  const tuning = host.hints.filter(
    (h) => h.startsWith("conntrack") || h === "cpuSoftIRQ",
  );
  return (
    <div className="flex flex-col gap-5">
      <div className="grid min-w-0 gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Gauge className="size-4 text-muted-foreground" />
              <CardTitle>{t("healthConntrack")}</CardTitle>
              <HelpTip>{t("healthConntrackHelp")}</HelpTip>
            </div>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex items-end justify-between gap-3">
              <span className="stat-value">
                <bdi dir="ltr">{pct(host.conntrack_percent)}</bdi>
              </span>
              <span className="text-xs text-muted-foreground tabular-nums">
                <bdi dir="ltr">
                  {n(host.conntrack_count)} / {n(host.conntrack_max)}
                </bdi>
              </span>
            </div>
            <Meter
              value={host.conntrack_percent}
              label={t("healthConntrack")}
            />
            <dl className="flex flex-col gap-2">
              <Row
                label={t("healthBuckets")}
                value={n(host.conntrack_buckets)}
              />
              <Row
                text
                label={t("healthEstablished")}
                value={
                  host.tcp_established_timeout == null
                    ? "—"
                    : duration(host.tcp_established_timeout, locale)
                }
              />
              <Row
                label={`${t("healthDrops")} (${t("healthSinceLast")})`}
                value={n(host.drops + host.early_drops + host.insert_failed)}
              />
            </dl>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Cpu className="size-4 text-muted-foreground" />
              <CardTitle>{t("healthCpu")}</CardTitle>
              <HelpTip>{t("healthCpuHelp")}</HelpTip>
            </div>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            {(
              [
                ["cpuUsage", host.cpu_percent, 70, 90],
                ["healthSteal", host.steal_percent, 5, 10],
                ["healthSoftirq", host.softirq_percent, 15, 25],
                ["healthIowait", host.iowait_percent, 10, 25],
              ] as const
            ).map(([key, value, warn, danger]) => (
              <div key={key} className="flex flex-col gap-1.5">
                <div className="flex items-baseline justify-between text-sm">
                  <span className="text-muted-foreground">{t(key)}</span>
                  <span className="font-medium tabular-nums">
                    <bdi dir="ltr">{pct(value)}</bdi>
                  </span>
                </div>
                <Meter
                  value={value}
                  label={t(key)}
                  warn={warn}
                  danger={danger}
                />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
      {!host.conntrack_cli && (
        <Alert>
          <TriangleAlert />
          <AlertDescription>{t("healthConntrackCliMissing")}</AlertDescription>
        </Alert>
      )}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Lightbulb className="size-4 text-muted-foreground" />
            <CardTitle>{t("healthRecommendations")}</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {host.hints.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t("healthAllGood")}
            </p>
          ) : (
            <ul className="flex flex-col gap-2">
              {host.hints.map((hint) => (
                <li key={hint} className="hint-row">
                  <TriangleAlert className="size-4 shrink-0" />
                  <span className="text-sm">{t(`hint_${hint}`)}</span>
                </li>
              ))}
            </ul>
          )}
          {tuning.length > 0 && (
            <div>
              <Button variant="outline" size="sm" asChild>
                <a href={routeURL("optimize")}>
                  {t("healthOpenOptimize")}
                  <ArrowUpRight data-icon="inline-end" />
                </a>
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
