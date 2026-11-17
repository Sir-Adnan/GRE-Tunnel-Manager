import { Pencil } from "lucide-react";
import { ActionButton } from "@/components/help";
import { Blank, EngineGlyph, Status } from "@/components/shared";
import { connectionStatus } from "@/lib/connection-filters";
import { engineName } from "@/lib/format";
import { useT } from "@/lib/i18n";
import type { Connection } from "@/lib/api";
import { connectionTone } from "@/lib/connection-tone";
import { LiveRateBadge } from "@/features/traffic/live";
import { RouteChain, StatusChip } from "./RouteChain";

// The dashboard's connection list is a quick scan, not a second CRUD
// workspace: state, name, live speed and the route. Each row is a route
// host, so on a narrow row the route stacks (listener above destination)
// instead of splitting an address, exactly as on the connection cards.
export function ConnectionSummary({
  connections,
  limit = 6,
  onAdd,
  onEdit,
}: {
  connections: Connection[];
  limit?: number;
  onAdd: () => void;
  onEdit: (connection: Connection) => void;
}) {
  const t = useT();
  if (!connections.length) return <Blank onAdd={onAdd} />;
  return (
    <ul className="dash-conn-list" aria-label={t("recent")}>
      {connections.slice(0, limit).map((row) => {
        const tone = connectionTone({
          status: connectionStatus(row),
          enabled: row.enabled,
        });
        return (
          <li key={row.id} className="route-host dash-conn-row">
            <div className="dash-conn-grid">
              <div className="dash-conn-id">
                <StatusChip tone={tone} />
                <div className="min-w-0">
                  <p className="bidi-name font-medium [overflow-wrap:anywhere]">
                    {row.name}
                  </p>
                  <p className="flex items-center gap-1 text-xs text-muted-foreground">
                    <EngineGlyph engine={row.engine} className="size-3.5" />
                    <bdi>{engineName(row.engine)}</bdi>
                  </p>
                </div>
              </div>
              <div className="dash-conn-route">
                <RouteChain connection={row} tone={tone} />
              </div>
              <LiveRateBadge id={row.id} className="dash-conn-live is-column" />
              <div className="dash-conn-actions">
                <Status value={connectionStatus(row)} tone={tone} />
                <ActionButton
                  variant="ghost"
                  size="icon"
                  label={`${t("edit")} ${row.name}`}
                  onClick={() => onEdit(row)}
                >
                  <Pencil />
                </ActionButton>
              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}
