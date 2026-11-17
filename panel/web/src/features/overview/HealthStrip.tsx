// Tunnel health on the dashboard: worst first, each with its last 24 hours
// as small bars and its uptime. The Health page has the details.
import { useContext } from "react";
import { ChevronLeft, ChevronRight, HeartPulse } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SectionLink } from "@/components/shared";
import { LocaleContext, useT } from "@/lib/i18n";
import { StatusPill, UptimeBars } from "@/features/health/Indicators";
import { filterOwners } from "@/features/health/filter";
import { percent, stamp, uptimeTone } from "@/features/health/format";
import type { HealthView } from "@/features/operations/types";

const shown = 6;

export function HealthStrip({
  view,
  navigate,
}: {
  view?: HealthView;
  navigate: (page: string, params?: Record<string, string>) => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const owners = view ? filterOwners(view.owners, "all") : [];
  const on = Boolean(view?.settings.enabled);
  const hourStart = view
    ? Math.floor(new Date(view.time).getTime() / 3600000) * 3600000
    : 0;
  const Chevron = locale === "fa" ? ChevronLeft : ChevronRight;
  return (
    <Card className="dash-health">
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <CardTitle className="flex items-center gap-2">
            <HeartPulse aria-hidden className="size-4" />
            {t("dashHealthTitle")}
          </CardTitle>
          {on && owners.length > 0 && (
            <SectionLink onClick={() => navigate("health")}>
              {t("dashOpenHealth")}
            </SectionLink>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {!view ? null : !on || owners.length === 0 ? (
          <div className="flex flex-col items-start gap-3">
            <p className="text-sm leading-6 text-muted-foreground">
              {t("dashHealthEmpty")}
            </p>
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate("health")}
            >
              {t("dashOpenHealth")}
            </Button>
          </div>
        ) : (
          <ul className="dash-health-list">
            {owners.slice(0, shown).map((owner) => (
              <li key={owner.owner} className="dash-health-row">
                <span className="dash-health-name">
                  <button
                    type="button"
                    className="dash-health-link"
                    onClick={() => navigate("health")}
                  >
                    <bdi>{owner.name}</bdi>
                  </button>
                  <StatusPill status={owner.status} />
                </span>
                <span
                  className="dash-health-uptime"
                  data-tone={uptimeTone(owner.uptime_24h)}
                >
                  <bdi dir="ltr">{percent(owner.uptime_24h, locale)}</bdi>
                </span>
                <UptimeBars
                  className="dash-health-bars"
                  cells={owner.hours}
                  label={`${t("healthLast24h")} · ${owner.name}`}
                  cellLabel={(i) =>
                    stamp(
                      hourStart - (23 - i) * 3600000,
                      locale,
                      view.timezone,
                      false,
                    )
                  }
                />
                <Chevron aria-hidden className="dash-health-chevron" />
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
