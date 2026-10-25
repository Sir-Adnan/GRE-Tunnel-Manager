import { useState, lazy, Suspense } from "react";
import { Code2, Plus, FileUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ActionButton } from "@/components/help";
import { PageTitle } from "@/components/shared";
import { useT } from "@/lib/i18n";
import type { Connection, Inventory } from "@/lib/api";
import { ConnectionTable } from "./ConnectionTable";
const ConfigurationImport = lazy(() =>
  import("../configuration/ConfigurationImport").then((m) => ({
    default: m.ConfigurationImport,
  })),
);

export function ConnectionWorkspace({
  page,
  inventory,
  add,
  edit,
  run,
}: {
  page: string;
  inventory: Inventory;
  add: () => void;
  edit: (connection: Connection) => void;
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const [importing, setImporting] = useState(false);
  const connections = inventory.connections.filter(
    (c) =>
      page === "connections" ||
      (page === "forwarding"
        ? ["nftables", "iptables"].includes(c.engine)
        : c.engine === page),
  );
  return (
    <div className="page-stack">
      <PageTitle
        title={
          page === "haproxy" ? "HAProxy" : page === "realm" ? "Realm" : t(page)
        }
        description={t("subtitle")}
        action={
          <div className="flex flex-wrap items-center gap-2">
            <Button onClick={add}>
              <Plus data-icon="inline-start" />
              {t("newConnection")}
            </Button>
            <Button
              variant="outline"
              aria-label={t("importConfiguration")}
              onClick={() => setImporting(true)}
            >
              <FileUp data-icon="inline-start" />
              {t("importShort")}
            </Button>
            <ActionButton
              variant="outline"
              size="icon"
              label={t("previewAllHelp")}
              onClick={() => void run({ action: "plan" }).catch(() => {})}
            >
              <Code2 />
            </ActionButton>
          </div>
        }
      />
      <Card>
        <CardContent>
          <ConnectionTable
            key={page}
            connections={connections}
            onAdd={add}
            onEdit={edit}
            run={run}
          />
        </CardContent>
      </Card>
      {importing && (
        <Suspense fallback={null}>
          <ConfigurationImport
            engine={
              page === "realm"
                ? "realm"
                : page === "forwarding"
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
