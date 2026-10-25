import { useContext } from "react";
import { Badge } from "@/components/ui/badge";
import { HelpTip } from "@/components/help";
import { LocaleContext, useT } from "@/lib/i18n";
import { trafficBytes } from "@/lib/format";
import type { Metrics, TrafficPolicy } from "@/lib/api";
import { quotaUsage } from "./accounting";

/** One compact quota presentation for tables, mobile rows and details. */
export function QuotaStatus({
  counter,
  policy,
  blocked = false,
}: {
  counter?: Metrics["counters"][string];
  policy?: TrafficPolicy;
  blocked?: boolean;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  if (!policy?.limit)
    return (
      <span className="text-xs text-muted-foreground">{t("noQuota")}</span>
    );
  const q = quotaUsage(counter, policy);
  return (
    <div className="flex min-w-0 flex-col items-start gap-1.5">
      <div className="flex flex-wrap items-center gap-1">
        <Badge
          variant="outline"
          className={q.reached ? "border-destructive/40" : undefined}
        >
          {blocked ? (
            t("quotaPaused")
          ) : q.reached ? (
            t("quotaReached")
          ) : (
            <bdi>{trafficBytes(policy.limit, locale)}</bdi>
          )}
        </Badge>
        {policy.stop_on_limit && (
          <HelpTip label={t("autoPause")}>{t("autoPauseHelp")}</HelpTip>
        )}
      </div>
      <span className="text-xs text-muted-foreground">
        <bdi dir="ltr">
          {counter ? trafficBytes(q.used, locale) : "—"} /{" "}
          {trafficBytes(policy.limit, locale)}
        </bdi>
        {" · "}
        {t(policy.direction)}
      </span>
      {counter && (
        <div
          className="h-1 w-24 overflow-hidden rounded-full bg-muted"
          role="progressbar"
          aria-label={t("cycleQuota")}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.round(q.percent)}
        >
          <div
            className={`h-full rounded-full ${q.reached ? "bg-destructive" : "bg-primary"}`}
            style={{ width: `${q.percent}%` }}
          />
        </div>
      )}
    </div>
  );
}
