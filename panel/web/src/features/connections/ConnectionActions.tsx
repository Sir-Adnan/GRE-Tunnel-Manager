import { Pencil, Play, Square, Trash2, FileText } from "lucide-react";
import { ActionButton } from "@/components/help";
import type { Connection } from "@/lib/api";
import { useT } from "@/lib/i18n";
export function ConnectionActions({
  row,
  busy,
  compact,
  onEdit,
  onDelete,
  onToggle,
  run,
}: {
  row: Connection;
  busy: boolean;
  compact: boolean;
  onEdit: (c: Connection) => void;
  onDelete: () => void;
  onToggle: () => void;
  run: (r: unknown) => Promise<void>;
}) {
  const t = useT();
  return (
    <div className="flex flex-wrap items-center justify-end gap-1">
      <ActionButton
        variant="ghost"
        size="icon"
        label={`${t("edit")} ${row.name}`}
        disabled={busy}
        onClick={() => onEdit(row)}
      >
        <Pencil />
      </ActionButton>
      {!compact && (
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
      )}
    </div>
  );
}
