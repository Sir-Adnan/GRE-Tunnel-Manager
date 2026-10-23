import { Pencil, Workflow, Network, Route } from "lucide-react";
import { ActionButton } from "@/components/help";
import { Blank, Status } from "@/components/shared";
import { engineName } from "@/lib/format";
import { useT } from "@/lib/i18n";
import type { Connection } from "@/lib/api";
import { Destinations } from "./Destinations";

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
          const Icon =
            row.engine === "haproxy"
              ? Workflow
              : row.engine === "realm"
                ? Network
                : Route;
          return (
            <li
              key={row.id}
              className="grid min-w-0 grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-3 py-3 @2xl:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)_auto]"
            >
              <div className="flex min-w-0 items-center gap-2.5">
                <span className="engine-icon" aria-hidden>
                  <Icon className="size-4" />
                </span>
                <div className="min-w-0">
                  <p className="font-medium [overflow-wrap:anywhere]">
                    {row.name}
                  </p>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    <bdi>{engineName(row.engine)}</bdi>
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-1 @2xl:col-start-3 @2xl:row-start-1">
                <Status
                  value={
                    row.status || (row.enabled ? "configured" : "disabled")
                  }
                />
                <ActionButton
                  variant="ghost"
                  size="icon"
                  label={`${t("edit")} ${row.name}`}
                  onClick={() => onEdit(row)}
                >
                  <Pencil />
                </ActionButton>
              </div>
              <dl className="col-span-2 grid min-w-0 grid-cols-[minmax(0,0.65fr)_minmax(0,1.35fr)] gap-3 @2xl:col-span-1 @2xl:col-start-2 @2xl:row-start-1">
                <div className="min-w-0">
                  <dt className="mb-1 text-xs text-muted-foreground">
                    {t("listener")}
                  </dt>
                  <dd className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                    <bdi dir="ltr" className="break-all font-mono text-xs">
                      {row.ports}
                    </bdi>
                    <span className="text-xs text-muted-foreground">
                      {row.protocol.toUpperCase()}
                    </span>
                  </dd>
                </div>
                <div className="min-w-0">
                  <dt className="mb-1 text-xs text-muted-foreground">
                    {t("destination")}
                  </dt>
                  <dd className="flex min-w-0">
                    <Destinations connection={row} />
                  </dd>
                </div>
              </dl>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
