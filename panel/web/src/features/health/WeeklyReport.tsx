import { useContext, useState } from "react";
import { Download, Printer } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Choice } from "@/components/shared";
import { number, trafficBytes, engineName } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import { useHealthReport } from "@/features/operations/hooks";
import type { HealthReport } from "@/features/operations/types";
import {
  dayLabel,
  duration,
  milliseconds,
  outageSeconds,
  percent,
  reportCSV,
  uptimeTone,
} from "./format";

function Tile({
  label,
  value,
  tone,
  text = false,
}: {
  label: string;
  value: string;
  tone?: string;
  /** Localized words (durations) keep the page direction; numbers stay LTR. */
  text?: boolean;
}) {
  return (
    <div className="report-tile" data-tone={tone}>
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="report-tile-value">
        <bdi dir={text ? undefined : "ltr"}>{value}</bdi>
      </span>
    </div>
  );
}

function download(report: HealthReport, headers: string) {
  const data = reportCSV(report, headers.split(","));
  const url = URL.createObjectURL(
    new Blob(["﻿", data], { type: "text/csv;charset=utf-8" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = `tunnel-health-${report.start.slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

/** Calendar-week summary: uptime, outages, latency, server load and maintenance. */
export function WeeklyReport() {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [week, setWeek] = useState(0);
  // Persian weeks start on Saturday; English weeks on Monday.
  const weekStart = locale === "fa" ? 6 : 1;
  const { value: report, error } = useHealthReport(week, weekStart);
  if (error)
    return (
      <Alert variant="destructive">
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  if (!report) return <Skeleton className="h-72 w-full" />;
  const tz = report.timezone;
  const end = new Date(new Date(report.end).getTime() - 1);
  const results = report.maintenance.reduce<Record<string, number>>(
    (acc, e) => {
      acc[e.result] = (acc[e.result] ?? 0) + 1;
      return acc;
    },
    {},
  );
  const weekOptions = Array.from({ length: report.weeks }, (_, i) => ({
    value: String(i),
    label:
      i === 0
        ? t("healthThisWeek")
        : i === 1
          ? t("healthLastWeek")
          : t("healthWeeksAgo").replace("{n}", String(i)),
  }));
  return (
    <div className="weekly-report flex flex-col gap-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex min-w-0 flex-col gap-1">
          <h2 className="text-lg font-semibold tracking-tight">
            {t("healthReportTab")}
          </h2>
          <p className="text-sm text-muted-foreground">
            <bdi>
              {t("healthReportRange")
                .replace("{a}", dayLabel(report.start, locale, tz))
                .replace("{b}", dayLabel(end.toISOString(), locale, tz))}
            </bdi>{" "}
            · <bdi dir="ltr">{tz}</bdi>
          </p>
        </div>
        <div className="report-actions flex flex-wrap items-end gap-2">
          <div className="w-44">
            <Choice
              id="report-week"
              label={t("healthReportWeek")}
              labelHidden
              value={String(week)}
              onChange={(v) => setWeek(Number(v))}
              choices={weekOptions}
            />
          </div>
          <Button
            variant="outline"
            onClick={() => download(report, t("healthCsvHeaders"))}
            disabled={!report.rows.length}
          >
            <Download data-icon="inline-start" />
            {t("exportCSV")}
          </Button>
          <Button variant="outline" onClick={() => window.print()}>
            <Printer data-icon="inline-start" />
            {t("healthPrint")}
          </Button>
        </div>
      </div>
      {!report.complete && (
        <p className="text-xs text-muted-foreground">
          {t("healthReportPartial")}
        </p>
      )}
      <div className="report-tiles">
        <Tile
          label={t("healthUptime")}
          value={percent(report.uptime, locale)}
          tone={uptimeTone(report.uptime)}
        />
        <Tile
          label={t("healthOutagesTab")}
          value={number(report.outages, locale)}
          tone={report.outages ? "warn" : "ok"}
        />
        <Tile
          label={t("healthDowntime")}
          value={duration(report.downtime_seconds, locale)}
          text
        />
        <Tile
          label={t("healthLongest")}
          text
          value={
            report.longest
              ? duration(
                  outageSeconds(report.longest, report.start, report.end),
                  locale,
                )
              : "—"
          }
        />
      </div>
      {report.rows.length === 0 ? (
        <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
          {t("healthReportEmpty")}
        </p>
      ) : (
        <div className="table-frame rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("name")}</TableHead>
                <TableHead>{t("healthUptime")}</TableHead>
                <TableHead>{t("healthOutagesTab")}</TableHead>
                <TableHead>{t("healthDowntime")}</TableHead>
                <TableHead>{t("healthAvgLatency")}</TableHead>
                <TableHead>{t("healthMaxLatency")}</TableHead>
                <TableHead>{t("healthJitter")}</TableHead>
                <TableHead>{t("healthTraffic")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {report.rows.map((row) => {
                const traffic = report.traffic[row.owner];
                return (
                  <TableRow key={row.owner}>
                    <TableCell>
                      <div className="flex min-w-0 flex-col">
                        <span className="font-medium">
                          <bdi>{row.name}</bdi>
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {engineName(row.engine)}
                          {row.removed && (
                            <Badge variant="outline" className="ms-2">
                              {t("healthRemoved")}
                            </Badge>
                          )}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell
                      className="tabular-nums"
                      data-tone={uptimeTone(row.uptime)}
                    >
                      <bdi dir="ltr">{percent(row.uptime, locale)}</bdi>
                    </TableCell>
                    <TableCell className="tabular-nums">
                      {number(row.outages, locale)}
                    </TableCell>
                    <TableCell className="tabular-nums">
                      {row.downtime_seconds
                        ? duration(row.downtime_seconds, locale)
                        : "—"}
                    </TableCell>
                    <TableCell className="tabular-nums">
                      <bdi dir="ltr">
                        {milliseconds(row.latency_ms, locale)}
                      </bdi>
                    </TableCell>
                    <TableCell className="tabular-nums">
                      <bdi dir="ltr">
                        {milliseconds(row.latency_max_ms, locale)}
                      </bdi>
                    </TableCell>
                    <TableCell className="tabular-nums">
                      <bdi dir="ltr">{milliseconds(row.jitter_ms, locale)}</bdi>
                    </TableCell>
                    <TableCell className="tabular-nums whitespace-nowrap">
                      <bdi dir="ltr">
                        {traffic
                          ? `${trafficBytes(traffic.received, locale)} / ${trafficBytes(traffic.sent, locale)}`
                          : "—"}
                      </bdi>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
      <div className="grid min-w-0 gap-5 md:grid-cols-2">
        <section className="report-section">
          <h3>{t("healthServerLoad")}</h3>
          <dl>
            {(
              [
                ["healthCpuAvg", report.host.cpu_percent],
                ["healthSteal", report.host.steal_percent],
                ["healthSoftirq", report.host.softirq_percent],
                ["healthConntrackPeak", report.host.conntrack_peak_percent],
              ] as const
            ).map(([key, value]) => (
              <div key={key}>
                <dt>{t(key)}</dt>
                <dd>
                  <bdi dir="ltr">
                    {value == null ? "—" : `${number(value, locale, 1)}%`}
                  </bdi>
                </dd>
              </div>
            ))}
            <div>
              <dt>{t("healthDrops")}</dt>
              <dd>
                <bdi dir="ltr">{number(report.host.drops, locale)}</bdi>
              </dd>
            </div>
          </dl>
        </section>
        <section className="report-section">
          <h3>{t("healthMaintenanceRuns")}</h3>
          {report.maintenance.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t("mxHistoryEmpty")}
            </p>
          ) : (
            <dl>
              {Object.entries(results).map(([result, count]) => (
                <div key={result}>
                  <dt>{t(`result_${result}`)}</dt>
                  <dd>
                    <bdi dir="ltr">{number(count, locale)}</bdi>
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </section>
      </div>
    </div>
  );
}
