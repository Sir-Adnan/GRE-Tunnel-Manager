import {
  Pencil,
  Play,
  Square,
  Trash2,
  FileText,
  Code2,
  MoreHorizontal,
  Info,
} from "lucide-react";
import { useContext } from "react";
import { LocaleContext } from "@/lib/i18n";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { ActionButton } from "@/components/help";
import type { Connection } from "@/lib/api";
import { useT } from "@/lib/i18n";
export function ConnectionActions({
  row,
  busy,
  onConfig,
  onDetails,
  onEdit,
  onDelete,
  onToggle,
  run,
}: {
  row: Connection;
  busy: boolean;
  onConfig: () => void;
  onDetails: () => void;
  onEdit: (c: Connection) => void;
  onDelete: () => void;
  onToggle: () => void;
  run: (r: unknown) => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  return (
    <div className="flex items-center justify-end gap-1">
      <ActionButton
        variant="ghost"
        size="icon"
        label={`${t("edit")} ${row.name}`}
        disabled={busy}
        onClick={() => onEdit(row)}
      >
        <Pencil />
      </ActionButton>
      <DropdownMenu dir={locale === "fa" ? "rtl" : "ltr"}>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            disabled={busy}
            aria-label={`${t("moreActions")} ${row.name}`}
          >
            <MoreHorizontal />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="min-w-48">
          <DropdownMenuGroup>
            <DropdownMenuItem onSelect={onDetails}>
              <Info />
              {t("connectionDetails")}
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={onConfig}>
              <Code2 />
              {t("viewConfig")}
            </DropdownMenuItem>
            {["realm", "haproxy"].includes(row.engine) && (
              <DropdownMenuItem
                onSelect={() =>
                  void run({ action: "logs", service: `gtm-${row.id}` }).catch(
                    () => {},
                  )
                }
              >
                <FileText />
                {t("logs")}
              </DropdownMenuItem>
            )}
            <DropdownMenuItem onSelect={onToggle}>
              {row.enabled ? <Square /> : <Play />}
              {t(row.enabled ? "disable" : "enable")}
            </DropdownMenuItem>
          </DropdownMenuGroup>
          <DropdownMenuSeparator />
          <DropdownMenuGroup>
            <DropdownMenuItem variant="destructive" onSelect={onDelete}>
              <Trash2 />
              {t("delete")}
            </DropdownMenuItem>
          </DropdownMenuGroup>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}
