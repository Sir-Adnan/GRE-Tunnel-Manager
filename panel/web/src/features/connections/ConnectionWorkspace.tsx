import { useContext, useState, lazy, Suspense } from "react";
import { Code2, Plus, FileUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ActionButton } from "@/components/help";
import { PageTitle } from "@/components/shared";
import { Segmented } from "@/components/Segmented";
import { LocaleContext, useT } from "@/lib/i18n";
import { number } from "@/lib/format";
import { usePanelRoute } from "@/lib/use-panel-route";
import {
  creationEngine,
  creationEngines,
  engineCounts,
  engineFilter,
  engineFilters,
  matchesEngine,
} from "@/lib/connection-filters";
import type { Connection, Inventory } from "@/lib/api";
import { ConnectionTable } from "./ConnectionTable";
const ConfigurationImport = lazy(() =>
  import("../configuration/ConfigurationImport").then((m) => ({
    default: m.ConfigurationImport,
  })),
);

const engineLabels: Record<string, string> = {
  all: "allEngines",
  kernel: "forwarding",
  haproxy: "HAProxy",
  realm: "Realm",
};

/** One Connections page for every listener engine; the engine filter lives in the URL. */
export function ConnectionWorkspace({
  inventory,
  add,
  edit,
  duplicate,
  run,
}: {
  inventory: Inventory;
  add: (engine: string, engines?: string[]) => void;
  edit: (connection: Connection) => void;
  duplicate: (connection: Connection) => void;
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { params, updateParams } = usePanelRoute();
  const [importing, setImporting] = useState(false);
  const engine = engineFilter(params.get("engine"));
  const counts = engineCounts(inventory.connections);
  const connections = inventory.connections.filter((c) =>
    matchesEngine(c.engine, engine),
  );
  const create = () => add(creationEngine(engine), creationEngines(engine));
  return (
    <div className="page-stack">
      <PageTitle
        title={t("connections")}
        description={t("connectionsHelp")}
        action={
          <div className="flex flex-wrap items-center gap-2">
            <ActionButton
              variant="outline"
              size="icon"
              label={t("previewAllHelp")}
              onClick={() => void run({ action: "plan" }).catch(() => {})}
            >
              <Code2 />
            </ActionButton>
            <Button
              variant="outline"
              aria-label={t("importConfiguration")}
              onClick={() => setImporting(true)}
            >
              <FileUp data-icon="inline-start" />
              {t("importShort")}
            </Button>
            <Button onClick={create}>
              <Plus data-icon="inline-start" />
              {t("newConnection")}
            </Button>
          </div>
        }
      />
      <Segmented
        label={t("engine")}
        value={engine}
        onChange={(value) =>
          updateParams({ engine: value === "all" ? "" : value, connection: "" })
        }
        options={engineFilters.map((id) => ({
          value: id,
          label:
            id === "haproxy" || id === "realm"
              ? engineLabels[id]
              : t(engineLabels[id]),
          count: number(counts[id], locale),
        }))}
      />
      <Card>
        <CardContent>
          <ConnectionTable
            key={engine}
            connections={connections}
            onAdd={create}
            onEdit={edit}
            onDuplicate={duplicate}
            run={run}
            inventory={inventory}
          />
        </CardContent>
      </Card>
      {importing && (
        <Suspense fallback={null}>
          <ConfigurationImport
            engine={
              engine === "realm"
                ? "realm"
                : engine === "kernel"
                  ? "nftables"
                  : "haproxy"
            }
            run={run}
            onClose={() => setImporting(false)}
          />
        </Suspense>
      )}
    </div>
  );
}
