import {
  Pencil,
  Trash2,
  FileText,
  Code2,
  MoreHorizontal,
  Info,
} from "lucide-react";
import { useContext } from "react";
import { LocaleContext } from "@/lib/i18n";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
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

/** Row actions: an explicit on/off switch, edit, and everything else in one menu. */
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
  const toggle = `${t(row.enabled ? "disable" : "enable")} ${row.name}`;
  return (
    <div
      className="row-actions"
      role="group"
      aria-label={`${t("actions")} ${row.name}`}
    >
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="inline-flex min-h-9 items-center px-1.5">
            <Switch
              size="sm"
              aria-label={toggle}
              checked={row.enabled}
              disabled={busy}
              onCheckedChange={onToggle}
            />
          </span>
        </TooltipTrigger>
        <TooltipContent>{toggle}</TooltipContent>
      </Tooltip>
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
        <DropdownMenuContent align="end" className="min-w-52">
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
