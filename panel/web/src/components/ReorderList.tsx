// Reordering is a mode, not a permanent handle: a compact, numbered list shown
// while the person chose "Reorder". A row drags by its handle, by a press and
// hold anywhere on it (touch), with the arrow keys on the handle, or from its
// ⋯ menu (top, up, down, bottom). Moves stay here until Save; Cancel puts the
// list back. The Save bar floats like the selection bar, so it stays in reach
// in a long list.
import { useContext, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { ArrowUpDown, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ActionMenu } from "@/components/ActionMenu";
import { DragHandle, SortableArea, SortableItem } from "@/components/sortable";
import { useMoveBy } from "@/lib/use-sortable-item";
import { moveActions } from "@/lib/move-actions";
import { LocaleContext, useT } from "@/lib/i18n";
import { number } from "@/lib/format";

export type ReorderItem = {
  id: string;
  /** The accessible name and visible title. */
  label: string;
  /** A small mark before the title, such as a status icon. */
  leading?: ReactNode;
  /** A short secondary line. */
  meta?: ReactNode;
};

function Row({
  item,
  index,
  count,
  position,
  moved,
}: {
  item: ReorderItem;
  index: number;
  count: number;
  /** One-based place, live while a drag runs. */
  position: number;
  moved: boolean;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const moveBy = useMoveBy();
  return (
    <SortableItem id={item.id}>
      {(sortable) => (
        <li
          ref={sortable.setNodeRef}
          style={sortable.style}
          data-dragging={sortable.dragging || undefined}
          className="reorder-row"
          {...sortable.press}
        >
          <DragHandle handle={sortable.handle} label={item.label} />
          <span
            className="reorder-pos"
            data-moved={moved || undefined}
            aria-hidden
          >
            {number(position, locale)}
          </span>
          {item.leading}
          <span className="reorder-text">
            <span className="bidi-name truncate font-medium">{item.label}</span>
            {item.meta && <span className="reorder-meta">{item.meta}</span>}
          </span>
          <ActionMenu
            label={t("moveItem").replace("{name}", item.label)}
            title={item.label}
            groups={[
              moveActions(t, (delta) => moveBy?.(item.id, delta), index, count),
            ]}
          />
        </li>
      )}
    </SortableItem>
  );
}

export function ReorderList({
  items,
  label,
  onSave,
  onCancel,
}: {
  /** The rows in their saved order. */
  items: ReorderItem[];
  /** Names the list (heading and assistive technology). */
  label: string;
  /** Receives every id in its new order; resolves once saved (or failed). */
  onSave: (next: string[]) => Promise<unknown>;
  onCancel: () => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const saved = items.map((item) => item.id);
  const [order, setOrder] = useState(saved);
  const [preview, setPreview] = useState<string[] | null>(null);
  const [saving, setSaving] = useState(false);
  // Rows added or removed meanwhile (another tab) join or leave the draft.
  const ids = [
    ...order.filter((id) => saved.includes(id)),
    ...saved.filter((id) => !order.includes(id)),
  ];
  const byId = new Map(items.map((item) => [item.id, item]));
  const live = preview ?? ids;
  const changed = ids.some((id, index) => saved[index] !== id);
  async function save() {
    if (!changed) return onCancel();
    setSaving(true);
    try {
      await onSave(ids);
    } finally {
      setSaving(false);
    }
  }
  return (
    <section className="reorder-panel" aria-label={label}>
      <header className="reorder-head">
        <span className="reorder-head-icon" aria-hidden>
          <ArrowUpDown />
        </span>
        <span className="min-w-0">
          <span className="block font-medium">{label}</span>
          <span className="reorder-hint">{t("reorderHint")}</span>
        </span>
      </header>
      <SortableArea ids={ids} onMove={setOrder} onPreview={setPreview}>
        <ol className="reorder-list">
          {ids.map((id, index) => {
            const position = live.indexOf(id) + 1;
            return (
              <Row
                key={id}
                item={byId.get(id)!}
                index={index}
                count={ids.length}
                position={position}
                moved={saved[position - 1] !== id}
              />
            );
          })}
        </ol>
      </SortableArea>
      {createPortal(
        <div
          className="selection-bar reorder-actions"
          role="toolbar"
          aria-label={label}
        >
          <span className="selection-count" aria-live="polite">
            {changed ? (
              t("orderChanged")
            ) : (
              <span className="font-normal text-muted-foreground">
                {t("orderUnchanged").replace("{n}", number(ids.length, locale))}
              </span>
            )}
          </span>
          {changed && (
            <Button
              size="sm"
              variant="ghost"
              disabled={saving}
              onClick={onCancel}
            >
              {t("cancel")}
            </Button>
          )}
          <Button size="sm" disabled={saving} onClick={() => void save()}>
            {saving && (
              <Loader2 className="animate-spin" data-icon="inline-start" />
            )}
            {changed ? t("saveOrder") : t("done")}
          </Button>
        </div>,
        document.body,
      )}
    </section>
  );
}
