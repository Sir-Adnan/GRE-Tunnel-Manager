import { Code2, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { HelpTip } from "@/components/help";
import { PageTitle } from "@/components/shared";
import { useT } from "@/lib/i18n";
import type { Connection, Inventory } from "@/lib/api";
import { ConnectionTable } from "./ConnectionTable";

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
            <Button
              variant="outline"
              onClick={() => void run({ action: "plan" }).catch(() => {})}
            >
              <Code2 data-icon="inline-start" />
              {t("previewAll")}
            </Button>
            <HelpTip>{t("previewAllHelp")}</HelpTip>
            <Button onClick={add}>
              <Plus data-icon="inline-start" />
              {t("newConnection")}
            </Button>
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
    </div>
  );
}
