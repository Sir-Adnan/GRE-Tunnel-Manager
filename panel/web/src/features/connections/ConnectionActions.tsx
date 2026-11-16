import {
  Pencil,
  Trash2,
  FileText,
  Code2,
  Info,
  Stethoscope,
  CopyPlus,
} from "lucide-react";
import { useState } from "react";
import { DiagnoseDialog } from "@/features/diagnose/DiagnoseDialog";
import { ActionMenu } from "@/components/ActionMenu";
import { Switch } from "@/components/ui/switch";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { ActionButton } from "@/components/help";
import type { Connection } from "@/lib/api";
import { useT } from "@/lib/i18n";

/** Row actions: an explicit on/off switch, edit, and everything else in one menu (a sheet on phones). */
export function ConnectionActions({
  row,
  busy,
  onConfig,
  onDetails,
  onEdit,
  onDuplicate,
  onDelete,
  onToggle,
  run,
  menuOpen,
  onMenuOpenChange,
}: {
  row: Connection;
  busy: boolean;
  onConfig: () => void;
  onDetails: () => void;
  onEdit: (c: Connection) => void;
  onDuplicate?: (c: Connection) => void;
  onDelete: () => void;
  onToggle: () => void;
  run: (r: unknown) => Promise<void>;
  /** Lets a card swipe open this row's menu. */
  menuOpen?: boolean;
  onMenuOpenChange?: (open: boolean) => void;
}) {
  const t = useT();
  const toggle = `${t(row.enabled ? "disable" : "enable")} ${row.name}`;
  const [diagnosing, setDiagnosing] = useState(false);
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
      <ActionMenu
        label={`${t("moreActions")} ${row.name}`}
        title={row.name}
        disabled={busy}
        open={menuOpen}
        onOpenChange={onMenuOpenChange}
        groups={[
          [
            {
              id: "details",
              label: t("connectionDetails"),
              icon: <Info />,
              onSelect: onDetails,
            },
            {
              id: "config",
              label: t("viewConfig"),
              icon: <Code2 />,
              onSelect: onConfig,
            },
            ...(onDuplicate
              ? [
                  {
                    id: "duplicate",
                    label: t("duplicate"),
                    icon: <CopyPlus />,
                    onSelect: () => onDuplicate(row),
                  },
                ]
              : []),
            {
              id: "diagnose",
              label: t("diagOpen"),
              icon: <Stethoscope />,
              onSelect: () => setDiagnosing(true),
            },
            ...(["realm", "haproxy"].includes(row.engine)
              ? [
                  {
                    id: "logs",
                    label: t("logs"),
                    icon: <FileText />,
                    onSelect: () =>
                      void run({
                        action: "logs",
                        service: `gtm-${row.id}`,
                      }).catch(() => {}),
                  },
                ]
              : []),
          ],
          [
            {
              id: "delete",
              label: t("delete"),
              icon: <Trash2 />,
              onSelect: onDelete,
              destructive: true,
            },
          ],
        ]}
      />
      <DiagnoseDialog
        key={String(diagnosing)}
        owner={diagnosing ? row.id : undefined}
        name={row.name}
        onClose={() => setDiagnosing(false)}
      />
    </div>
  );
}
