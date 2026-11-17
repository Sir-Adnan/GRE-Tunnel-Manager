// Live throughput components: the page's one poll (provider) and the
// per-connection badge. State and hooks: ./use-live.ts.
import type { ReactNode } from "react";
import { useContext } from "react";
import { ArrowDown, ArrowUp } from "lucide-react";
import { bitRate } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import { LiveContext, useLive, useLiveTraffic } from "./use-live";

export function LiveTrafficProvider({
  enabled = true,
  uncounted,
  children,
}: {
  enabled?: boolean;
  /** Ids shown but left out of the combined total (GRE tunnels). */
  uncounted?: ReadonlySet<string>;
  children: ReactNode;
}) {
  const live = useLiveTraffic(enabled, uncounted);
  return <LiveContext.Provider value={live}>{children}</LiveContext.Provider>;
}

/**
 * One connection's live rate: down and up, as on the dashboard. Renders
 * nothing until a rate exists, so lists without collection stay quiet.
 */
export function LiveRateBadge({
  id,
  className,
}: {
  id: string;
  className?: string;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const { ready, rates } = useLive();
  const r = rates[id];
  if (!ready || !r) return null;
  const idleNow = r.received + r.sent < 1;
  return (
    <span
      className={className ? `live-rate ${className}` : "live-rate"}
      data-idle={idleNow || undefined}
      title={t("liveRateHelp")}
    >
      <span className="sr-only">{t("liveRate")}: </span>
      <span className="live-rate-dir">
        <ArrowDown aria-hidden />
        <span className="sr-only">{t("received")} </span>
        <bdi dir="ltr">{bitRate(r.received, locale)}</bdi>
      </span>
      <span className="live-rate-dir">
        <ArrowUp aria-hidden />
        <span className="sr-only">{t("sent")} </span>
        <bdi dir="ltr">{bitRate(r.sent, locale)}</bdi>
      </span>
    </span>
  );
}
