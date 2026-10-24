import { useContext } from "react";
import { Archive, Upload } from "lucide-react";
import { LocaleContext, useT } from "@/lib/i18n";
import type { Inventory } from "@/lib/api";
import { PageTitle } from "@/components/shared";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { usePanelRoute } from "@/lib/use-panel-route";
import { CreateBackup } from "./CreateBackup";
import { RestoreBackup } from "./RestoreBackup";
import { BackupScope } from "./BackupScope";

export function Backups({
  inventory,
  refreshed,
}: {
  inventory: Inventory;
  refreshed: () => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { params, updateParams } = usePanelRoute();
  const tab = params.get("tab") === "restore" ? "restore" : "create";
  return (
    <div className="page-stack">
      <PageTitle title={t("backups")} description={t("backupsIntro")} />
      <Tabs
        value={tab}
        onValueChange={(value) =>
          updateParams({ tab: value === "create" ? "" : value })
        }
        dir={locale === "fa" ? "rtl" : "ltr"}
        className="gap-5"
      >
        <TabsList>
          <TabsTrigger value="create">
            <Archive />
            {t("backupCreate")}
          </TabsTrigger>
          <TabsTrigger value="restore">
            <Upload />
            {t("backupRestore")}
          </TabsTrigger>
        </TabsList>
        <div className="grid min-w-0 items-start gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(16rem,22rem)]">
          <div className="min-w-0 rounded-xl border bg-card p-4 sm:p-6">
            <TabsContent
              value="create"
              forceMount
              className="data-[state=inactive]:hidden"
            >
              <CreateBackup />
            </TabsContent>
            <TabsContent
              value="restore"
              forceMount
              className="data-[state=inactive]:hidden"
            >
              <RestoreBackup inventory={inventory} refreshed={refreshed} />
            </TabsContent>
          </div>
          <BackupScope />
        </div>
      </Tabs>
    </div>
  );
}
