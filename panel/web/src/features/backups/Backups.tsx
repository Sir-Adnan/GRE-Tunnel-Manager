import { useContext } from "react";
import { Archive, CalendarClock, Upload } from "lucide-react";
import { LocaleContext, useT } from "@/lib/i18n";
import type { Inventory } from "@/lib/api";
import { PageTitle } from "@/components/shared";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { usePanelRoute } from "@/lib/use-panel-route";
import { CreateBackup } from "./CreateBackup";
import { RestoreBackup } from "./RestoreBackup";
import { BackupScope } from "./BackupScope";
import { Snapshots } from "./Snapshots";

export function Backups({
  inventory,
  refreshed,
  run,
}: {
  inventory: Inventory;
  refreshed: () => Promise<void>;
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { params, updateParams } = usePanelRoute();
  const tab = ["restore", "schedule"].includes(params.get("tab") ?? "")
    ? (params.get("tab") as string)
    : "create";
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
          <TabsTrigger value="schedule">
            <CalendarClock />
            {t("snapTab")}
          </TabsTrigger>
        </TabsList>
        <p className="max-w-prose text-sm text-muted-foreground">
          {t(
            tab === "schedule"
              ? "backupScheduleScope"
              : tab === "restore"
                ? "backupRestoreScope"
                : "backupDownloadScope",
          )}
        </p>
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
            <TabsContent
              value="schedule"
              className="data-[state=inactive]:hidden"
            >
              <Snapshots run={run} />
            </TabsContent>
          </div>
          <BackupScope />
        </div>
      </Tabs>
    </div>
  );
}
