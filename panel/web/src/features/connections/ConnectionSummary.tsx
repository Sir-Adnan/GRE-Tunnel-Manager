import { Pencil } from "lucide-react";
import { ActionButton } from "@/components/help";
import { Blank, EngineGlyph, Status } from "@/components/shared";
import { connectionStatus } from "@/lib/connection-filters";
import { engineName } from "@/lib/format";
import { useT } from "@/lib/i18n";
import type { Connection } from "@/lib/api";
import { connectionTone } from "@/lib/connection-tone";
import { RouteChain, StatusChip } from "./RouteChain";

// The overview is a quick scan, not a second CRUD workspace. Container queries
// keep rows compact even when this region is placed beside another dashboard.
export function ConnectionSummary({
  connections,
  onAdd,
  onEdit,
}: {
  connections: Connection[];
  onAdd: () => void;
  onEdit: (connection: Connection) => void;
}) {
  const t = useT();
  if (!connections.length) return <Blank onAdd={onAdd} />;
  return (
    <div className="@container min-w-0" data-connection-summary>
      <ul className="divide-y divide-border" aria-label={t("recent")}>
        {connections.slice(0, 5).map((row) => {
          // A quick scan: service state only; the Connections page adds health and firewall facts.
          const tone = connectionTone({
            status: connectionStatus(row),
            enabled: row.enabled,
          });
          return (
            <li
              key={row.id}
              className="grid min-w-0 grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-3 py-3 @2xl:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)_auto]"
            >
              <div className="flex min-w-0 items-center gap-2.5">
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
              <div className="flex items-center gap-1 @2xl:col-start-3 @2xl:row-start-1">
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
              <div className="col-span-2 min-w-0 @2xl:col-span-1 @2xl:col-start-2 @2xl:row-start-1">
                <RouteChain connection={row} tone={tone} />
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
