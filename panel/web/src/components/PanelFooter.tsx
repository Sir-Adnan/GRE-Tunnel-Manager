import { Archive, Server } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useT } from "@/lib/i18n";
import type { Inventory } from "@/lib/api";

export function PanelFooter({
  inventory,
  navigate,
}: {
  inventory?: Inventory;
  navigate: (page: string) => void;
}) {
  const t = useT();
  return (
    <footer className="app-footer">
      <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
        <bdi className="truncate">{inventory?.host.hostname}</bdi>
        <bdi>v{inventory?.version || "1.3.4"}</bdi>
      </div>
      <div className="flex shrink-0 items-center gap-1">
        <Button size="sm" variant="ghost" onClick={() => navigate("backups")}>
          <Archive data-icon="inline-start" />
          <span className="hidden sm:inline">{t("backups")}</span>
          <span className="sr-only sm:hidden">{t("backups")}</span>
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => navigate("components")}
        >
          <Server data-icon="inline-start" />
          <span className="hidden sm:inline">{t("components")}</span>
          <span className="sr-only sm:hidden">{t("components")}</span>
        </Button>
      </div>
    </footer>
  );
}
