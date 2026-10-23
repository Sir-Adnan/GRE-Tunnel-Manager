import { Pencil, Play, Square, Trash2, FileText, Code2 } from "lucide-react";
import { ActionButton } from "@/components/help";
import type { Connection } from "@/lib/api";
import { useT } from "@/lib/i18n";
export function ConnectionActions({
  row,
  busy,
  onConfig,
  onEdit,
  onDelete,
  onToggle,
  run,
}: {
  row: Connection;
  busy: boolean;
  onConfig: () => void;
  onEdit: (c: Connection) => void;
  onDelete: () => void;
  onToggle: () => void;
  run: (r: unknown) => Promise<void>;
}) {
  const t = useT();
  return (
    <div className="flex flex-wrap items-center justify-end gap-1 [&_[data-slot=button]]:size-11 @3xl:[&_[data-slot=button]]:size-8 @3xl:[&_[data-slot=button]]:min-h-8">
      <ActionButton
        variant="ghost"
        size="icon"
        label={`${t("viewConfig")} ${row.name}`}
        onClick={onConfig}
      >
        <Code2 />
      </ActionButton>
      <ActionButton
        variant="ghost"
        size="icon"
        label={`${t("edit")} ${row.name}`}
        disabled={busy}
        onClick={() => onEdit(row)}
      >
        <Pencil />
      </ActionButton>
      {
        <>
          <ActionButton
            variant="ghost"
            size="icon"
            label={`${t(row.enabled ? "disable" : "enable")} ${row.name}`}
            disabled={busy}
            onClick={onToggle}
          >
            {row.enabled ? <Square /> : <Play />}
          </ActionButton>
          {["realm", "haproxy"].includes(row.engine) && (
            <ActionButton
              variant="ghost"
              size="icon"
              label={`${t("logs")} ${row.name}`}
              onClick={() =>
                void run({ action: "logs", service: `gtm-${row.id}` }).catch(
                  () => {},
                )
              }
            >
              <FileText />
            </ActionButton>
          )}
          <ActionButton
            variant="ghost"
            size="icon"
            label={`${t("delete")} ${row.name}`}
            disabled={busy}
            onClick={onDelete}
          >
            <Trash2 />
          </ActionButton>
        </>
      }
    </div>
  );
}
