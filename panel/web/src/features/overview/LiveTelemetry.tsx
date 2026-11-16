import { useContext, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  Cpu,
  MemoryStick,
  Pause,
  Play,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { HelpTip } from "@/components/help";
import { Segmented } from "@/components/Segmented";
import { LocaleContext, useT } from "@/lib/i18n";
import { bitRate, number, trafficBytes } from "@/lib/format";
import { Sparkline } from "@/components/Sparkline";
import { useHostTelemetry } from "./useHostTelemetry";

/** Dashboard sampling choices in seconds. Below 1 s the network rate is noise. */
const liveIntervals = [1, 2, 5, 15] as const;
const liveKey = "gtm.live-interval.v1";

function storedInterval(): number {
  try {
    const value = Number(globalThis.localStorage?.getItem(liveKey));
    return (liveIntervals as readonly number[]).includes(value) ? value : 2;
  } catch {
    return 2;
  }
}

export function LiveTelemetry() {
  const t = useT(),
    locale = useContext(LocaleContext);
  const [enabled, setEnabled] = useState(true);
  const [interval, setStoredInterval] = useState(storedInterval);
  const setSampleInterval = (value: number) => {
    setStoredInterval(value);
    try {
      globalThis.localStorage?.setItem(liveKey, String(value));
    } catch {
      /* blocked storage: the choice lasts for this page only */
    }
  };
  const { sample, trends, error } = useHostTelemetry(enabled, interval);
  const stale = error;
  const ready = !stale;
  const memory = sample?.memory_total
    ? (100 * (sample.memory_total - sample.memory_available)) /
      sample.memory_total
    : undefined;
  const items = [
    {
      key: "cpuUsage",
      icon: Cpu,
      value:
        ready && sample?.cpu_percent != null
          ? `${number(sample.cpu_percent, locale, 1)}%`
          : "—",
      percent: ready ? sample?.cpu_percent : undefined,
      trend: trends.cpu,
      max: 100,
      detail: t("allCPUCores"),
    },
    {
      key: "memory",
      icon: MemoryStick,
      value: ready && memory != null ? `${number(memory, locale, 1)}%` : "—",
      percent: ready ? memory : undefined,
      trend: trends.memory,
      max: 100,
      detail:
        ready && sample?.memory_total
          ? `${trafficBytes(sample.memory_total - sample.memory_available, locale)} / ${trafficBytes(sample.memory_total, locale)}`
          : "—",
    },
    {
      key: "networkReceive",
      icon: ArrowDown,
      value: bitRate(ready ? sample?.received_per_second : null, locale),
      trend: trends.received,
      detail:
        ready && sample?.received_per_second != null
          ? `${trafficBytes(sample.received_per_second, locale)}/s`
          : t("waitingSample"),
    },
    {
      key: "networkSend",
      icon: ArrowUp,
      value: bitRate(ready ? sample?.sent_per_second : null, locale),
      trend: trends.sent,
      detail:
        ready && sample?.sent_per_second != null
          ? `${trafficBytes(sample.sent_per_second, locale)}/s`
          : t("waitingSample"),
    },
  ];
  return (
    <Card data-testid="live-telemetry">
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <CardTitle>{t("serverLive")}</CardTitle>
            <HelpTip>{t("serverLiveHelp")}</HelpTip>
            <Badge variant="outline">
              {t(
                !enabled
                  ? "livePaused"
                  : stale
                    ? "liveUnavailable"
                    : !sample || !sample.window_seconds
                      ? "waitingSample"
                      : "live",
              )}
            </Badge>
          </div>
          <div className="flex items-center gap-1">
            <Segmented
              label={t("liveInterval")}
              value={String(interval)}
              onChange={(value) => setSampleInterval(Number(value))}
              className="live-interval"
              options={liveIntervals.map((value) => ({
                value: String(value),
                label: <bdi dir="ltr">{value}s</bdi>,
              }))}
            />
            <Button
              variant="outline"
              size="sm"
              onClick={() => setEnabled(!enabled)}
            >
              {enabled ? (
                <Pause data-icon="inline-start" />
              ) : (
                <Play data-icon="inline-start" />
              )}
              {t(enabled ? "pauseLive" : "resumeLive")}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <dl className="grid grid-cols-2 gap-x-5 gap-y-6 lg:grid-cols-4">
          {items.map(
            ({ key, icon: Icon, value, percent, detail, trend, max }) => (
              <div key={key} className="flex min-w-0 flex-col gap-2">
                <dt className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Icon className="size-4 shrink-0" />
                  {t(key)}
                </dt>
                <dd className="text-title font-semibold tracking-tight tabular-nums sm:text-[1.5rem]">
                  <bdi dir="ltr">{value}</bdi>
                </dd>
                <dd className="min-h-4 break-words text-xs text-muted-foreground">
                  <bdi>{detail}</bdi>
                </dd>
                <dd aria-hidden className="h-6">
                  {ready && (
                    <Sparkline values={trend} max={max} className="is-wide" />
                  )}
                </dd>
                {percent != null && (
                  <dd
                    className="h-1 overflow-hidden rounded-full bg-muted"
                    role="meter"
                    aria-label={t(key)}
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={Math.round(percent)}
                  >
                    <div
                      className="h-full rounded-full bg-primary"
                      style={{
                        width: `${Math.max(0, Math.min(100, percent))}%`,
                      }}
                    />
                  </dd>
                )}
              </div>
            ),
          )}
        </dl>
        <div className="flex flex-wrap items-center justify-between gap-2 border-t pt-3 text-xs text-muted-foreground">
          <span>
            {t("defaultRouteInterfaces")}{" "}
            <bdi dir="ltr">{sample?.interfaces.join(", ") || "—"}</bdi>
          </span>
          <span>
            {t("lastSample")}{" "}
            <bdi>
              {sample
                ? new Date(sample.time).toLocaleTimeString(
                    locale === "fa" ? "fa-IR-u-nu-latn" : "en-US",
                  )
                : "—"}
            </bdi>
          </span>
        </div>
        {sample?.error && (
          <p className="text-xs text-muted-foreground" role="status">
            {t("livePartial")}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
