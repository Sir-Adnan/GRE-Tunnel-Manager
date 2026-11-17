import { useContext, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { EngineGlyph, SectionLink } from "@/components/shared";
import { ConnectionSummary } from "@/features/connections/ConnectionSummary";
import { useHealthView } from "@/features/operations/hooks";
import { LiveTrafficProvider } from "@/features/traffic/live";
import { engineName, number } from "@/lib/format";
import { attentionItems } from "@/lib/attention";
import { engineCounts } from "@/lib/connection-filters";
import { LocaleContext, useT } from "@/lib/i18n";
import type { Connection, Inventory } from "@/lib/api";
import { AttentionPanel } from "./overview/AttentionPanel";
import { DashboardFigures } from "./overview/DashboardFigures";
import { GettingStarted } from "./overview/GettingStarted";
import { HealthStrip } from "./overview/HealthStrip";
import { HostHeader } from "./overview/HostHeader";
import { LiveTelemetry } from "./overview/LiveTelemetry";

const shownConnections = 6;

/**
 * The dashboard, a live command center: the host, four figures (live
 * traffic, connections, 24-hour health, attention), then connections with
 * their live speed beside the server's load, tunnel health and what to fix.
 * One live-traffic poll and one health read serve the whole page.
 */
export function Overview({
  inventory,
  add,
  edit,
  navigate,
}: {
  inventory: Inventory;
  add: () => void;
  edit: (value: Connection) => void;
  navigate: (page: string, params?: Record<string, string>) => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const issues = attentionItems(inventory);
  const services = [
    ...inventory.connections.filter((c) => c.enabled),
    ...inventory.resources.filter((r) => r.configured),
  ];
  const running =
    inventory.connections.filter((c) =>
      ["active", "configured"].includes(c.status || ""),
    ).length + inventory.resources.filter((r) => r.status === "active").length;
  const counts = engineCounts(inventory.connections);
  // GRE bytes are the forwards' bytes again; keep them out of the total.
  const gre = useMemo(
    () =>
      new Set(
        inventory.resources.filter((r) => r.engine === "gre").map((r) => r.id),
      ),
    [inventory.resources],
  );
  const { value: health } = useHealthView();
  const total = inventory.connections.length;
  return (
    <LiveTrafficProvider uncounted={gre}>
      <div className="page-stack">
        <HostHeader host={inventory.host} add={add} navigate={navigate} />
        <GettingStarted
          connections={total + inventory.resources.length}
          add={add}
          navigate={navigate}
        />
        <section aria-label={t("overviewBlockKpi")}>
          <DashboardFigures
            connections={total}
            enabled={inventory.connections.filter((c) => c.enabled).length}
            running={running}
            services={services.length}
            issues={issues.length}
            health={health}
            navigate={navigate}
          />
        </section>
        <section className="dash-grid" aria-label={t("overviewBlockStatus")}>
          <div className="dash-main">
            <Card>
              <CardHeader>
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <CardTitle>{t("recent")}</CardTitle>
                  <div className="flex flex-wrap items-center gap-1">
                    {(["haproxy", "realm", "kernel"] as const)
                      .filter((id) => counts[id])
                      .map((id) => (
                        <Button
                          key={id}
                          size="sm"
                          variant="ghost"
                          onClick={() =>
                            navigate("connections", { engine: id })
                          }
                        >
                          <EngineGlyph
                            engine={id === "kernel" ? "nftables" : id}
                          />
                          {id === "kernel" ? t("forwarding") : engineName(id)}
                          <span className="text-muted-foreground tabular-nums">
                            {number(counts[id], locale)}
                          </span>
                        </Button>
                      ))}
                    <SectionLink onClick={() => navigate("connections")}>
                      {t("seeAll")}
                    </SectionLink>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <ConnectionSummary
                  connections={inventory.connections}
                  limit={shownConnections}
                  onAdd={add}
                  onEdit={edit}
                />
                {total > shownConnections && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="mt-2"
                    onClick={() => navigate("connections")}
                  >
                    {t("dashShowConnections").replace(
                      "{n}",
                      number(total, locale),
                    )}
                  </Button>
                )}
              </CardContent>
            </Card>
            <LiveTelemetry />
          </div>
          <aside className="dash-side">
            <AttentionPanel items={issues} navigate={navigate} />
            <HealthStrip view={health} navigate={navigate} />
          </aside>
        </section>
      </div>
    </LiveTrafficProvider>
  );
}
