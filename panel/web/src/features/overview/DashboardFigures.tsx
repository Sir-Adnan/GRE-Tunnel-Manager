// The dashboard's four figures: live traffic, connections, 24-hour health
// and what needs attention. Each opens the page behind it.
import { useContext } from "react";
import { Activity, CircleAlert, HeartPulse, Layers3 } from "lucide-react";
import { Sparkline } from "@/components/Sparkline";
import { bitRate, number } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import { percent, uptimeTone } from "@/features/health/format";
import type { HealthView } from "@/features/operations/types";
import { useLive } from "@/features/traffic/use-live";
import { Kpi } from "./Kpi";

type Navigate = (page: string, params?: Record<string, string>) => void;

function LiveTrafficFigure({ navigate }: { navigate: Navigate }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const live = useLive();
  const received = live.total.received.at(-1);
  const sent = live.total.sent.at(-1);
  const series = live.total.received.map(
    (r, i) => r + (live.total.sent[i] ?? 0),
  );
  if (live.enabled === false)
    return (
      <Kpi
        icon={Activity}
        label={t("dashLiveTraffic")}
        value="—"
        detail={t("dashLiveOff")}
        tone="muted"
        onClick={() => navigate("traffic")}
      />
    );
  const ready = live.ready && received != null && sent != null;
  return (
    <Kpi
      icon={Activity}
      label={t("dashLiveTraffic")}
      value={ready ? bitRate(received + sent, locale) : "…"}
      detail={
        ready ? (
          <span dir="ltr" className="kpi-rates">
            ↓ {bitRate(received, locale)} · ↑ {bitRate(sent, locale)}
          </span>
        ) : (
          t("dashLiveWaiting")
        )
      }
      trend={
        series.length > 1 ? (
          <Sparkline values={series} className="is-wide" />
        ) : undefined
      }
      onClick={() => navigate("traffic")}
    />
  );
}

export function DashboardFigures({
  connections,
  enabled,
  running,
  services,
  issues,
  health,
  navigate,
}: {
  connections: number;
  enabled: number;
  running: number;
  services: number;
  issues: number;
  health?: HealthView;
  navigate: Navigate;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const monitoring = Boolean(health?.settings.enabled);
  const summary = health?.summary;
  const tone = uptimeTone(summary?.uptime_24h ?? null);
  return (
    <div className="kpi-grid">
      <LiveTrafficFigure navigate={navigate} />
      <Kpi
        icon={Layers3}
        label={t("dashConnections")}
        value={`${number(running, locale)} / ${number(services, locale)}`}
        detail={`${t("dashRunning").replace("{n}", number(running, locale))} · ${number(enabled, locale)}/${number(connections, locale)} ${locale === "en" ? t("configured").toLowerCase() : t("configured")}`}
        tone={services && running < services ? "alert" : undefined}
        onClick={() => navigate("connections")}
      />
      <Kpi
        icon={HeartPulse}
        label={t("dashHealth")}
        value={monitoring ? percent(summary?.uptime_24h, locale) : "—"}
        detail={
          monitoring && summary
            ? t("dashHealthDetail")
                .replace("{up}", number(summary.up, locale))
                .replace("{all}", number(summary.owners, locale))
            : t("dashHealthOff")
        }
        tone={
          !monitoring
            ? "muted"
            : tone === "ok"
              ? "ok"
              : tone === "none"
                ? undefined
                : "alert"
        }
        onClick={() => navigate("health")}
      />
      <Kpi
        icon={CircleAlert}
        label={t("needsAttention")}
        value={number(issues, locale)}
        detail={t(issues ? "reviewIssues" : "allHealthy")}
        tone={issues ? "alert" : "ok"}
      />
    </div>
  );
}
