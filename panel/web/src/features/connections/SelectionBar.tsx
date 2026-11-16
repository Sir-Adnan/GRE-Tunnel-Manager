import { useContext } from "react";
import { createPortal } from "react-dom";
import { CheckCheck, Pause, Play, Trash2, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ActionButton } from "@/components/help";
import { LocaleContext, useT } from "@/lib/i18n";
import { number } from "@/lib/format";

/** Bulk actions float above the content (and the mobile navigation) while rows
 * are selected, or for the whole of selection mode (`open`).
 * Portaled to <body> so no animated ancestor can become its containing block. */
export function SelectionBar({
  count,
  busy,
  onEnable,
  onDisable,
  onDelete,
  onClear,
  open = false,
  onSelectAll,
}: {
  count: number;
  busy: boolean;
  onEnable: () => void;
  onDisable: () => void;
  onDelete: () => void;
  onClear: () => void;
  open?: boolean;
  /** Offered while some shown rows are not selected. */
  onSelectAll?: () => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  if (!count && !open) return null;

  return createPortal(
    <div
      className="selection-bar"
      role="toolbar"
      aria-label={t("selectionActions")}
    >
      <span className="selection-count" aria-live="polite">
        {count ? (
          <>
            <bdi>{number(count, locale)}</bdi> {t("selected")}
          </>
        ) : (
          <span className="font-normal text-muted-foreground">
            {t("selectHint")}
          </span>
        )}
      </span>
      {onSelectAll && (
        <ActionButton
          size="icon-sm"
          variant="ghost"
          label={t("selectAll")}
          onClick={onSelectAll}
        >
          <CheckCheck />
        </ActionButton>
      )}
      {count > 0 && (
        <>
          <Button
            size="sm"
            variant="ghost"
            aria-label={t("enable")}
            disabled={busy}
            onClick={onEnable}
          >
            <Play data-icon="inline-start" />
            <span className="hidden sm:inline">{t("enable")}</span>
          </Button>
          <Button
            size="sm"
            variant="ghost"
            aria-label={t("disable")}
            disabled={busy}
            onClick={onDisable}
          >
            <Pause data-icon="inline-start" />
            <span className="hidden sm:inline">{t("disable")}</span>
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="text-destructive-text"
            aria-label={t("delete")}
            disabled={busy}
            onClick={onDelete}
          >
            <Trash2 data-icon="inline-start" />
            <span className="hidden sm:inline">{t("delete")}</span>
          </Button>
        </>
      )}
      <ActionButton
        size="icon-sm"
        variant="ghost"
        label={t("clearSelection")}
        onClick={onClear}
      >
        <X />
      </ActionButton>
    </div>,
    document.body,
  );
}
