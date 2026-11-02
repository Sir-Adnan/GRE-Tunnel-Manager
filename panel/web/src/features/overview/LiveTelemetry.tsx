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
import { LocaleContext, useT } from "@/lib/i18n";
import { number, trafficBytes } from "@/lib/format";
import { useHostTelemetry } from "./useHostTelemetry";

function rate(bytes: number | null | undefined, locale: "en" | "fa") {
  if (bytes == null) return "—";
  const bits = Math.max(0, bytes) * 8;
  const unit = bits >= 1e9 ? 1e9 : bits >= 1e6 ? 1e6 : bits >= 1e3 ? 1e3 : 1;
  return `${number(bits / unit, locale, 1)} ${unit === 1e9 ? "Gbps" : unit === 1e6 ? "Mbps" : unit === 1e3 ? "Kbps" : "bps"}`;
}

export function LiveTelemetry() {
  const t = useT(),
    locale = useContext(LocaleContext);
  const [enabled, setEnabled] = useState(true);
  const [interval, setSampleInterval] = useState(5);
  const { sample, error } = useHostTelemetry(enabled, interval);
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
      detail: t("allCPUCores"),
    },
    {
      key: "memory",
      icon: MemoryStick,
      value: ready && memory != null ? `${number(memory, locale, 1)}%` : "—",
      percent: ready ? memory : undefined,
      detail:
        ready && sample?.memory_total
          ? `${trafficBytes(sample.memory_total - sample.memory_available, locale)} / ${trafficBytes(sample.memory_total, locale)}`
          : "—",
    },
    {
      key: "networkReceive",
      icon: ArrowDown,
      value: rate(ready ? sample?.received_per_second : null, locale),
      detail:
        ready && sample?.received_per_second != null
          ? `${trafficBytes(sample.received_per_second, locale)}/s`
          : t("waitingSample"),
    },
    {
      key: "networkSend",
      icon: ArrowUp,
      value: rate(ready ? sample?.sent_per_second : null, locale),
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
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setSampleInterval(interval === 5 ? 15 : 5)}
              aria-label={t("liveInterval")}
            >
              <bdi>{interval}s</bdi>
            </Button>
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
          {items.map(({ key, icon: Icon, value, percent, detail }) => (
            <div key={key} className="flex min-w-0 flex-col gap-2">
              <dt className="flex items-center gap-2 text-xs text-muted-foreground">
                <Icon className="size-4 shrink-0" />
                {t(key)}
              </dt>
              <dd className="text-xl font-semibold tracking-tight tabular-nums sm:text-2xl">
                <bdi dir="ltr">{value}</bdi>
              </dd>
              <dd className="min-h-4 break-words text-xs text-muted-foreground">
                <bdi>{detail}</bdi>
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
                    style={{ width: `${Math.max(0, Math.min(100, percent))}%` }}
                  />
                </dd>
              )}
            </div>
          ))}
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
