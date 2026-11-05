// Drag-and-drop reordering for any list, grid or table. A visible handle
// drags with mouse or touch; with the keyboard, focus the handle and press an
// arrow key to move the item one place (mirrored in right-to-left). Links and
// buttons in a row keep working and screen readers hear each move.
import { createContext, useContext, useState, type KeyboardEvent, type ReactNode } from "react";
import {
  DndContext,
  PointerSensor,
  TouchSensor,
  closestCorners,
  useSensor,
  useSensors,
  type DragEndEvent,
} from "@dnd-kit/core";
import { SortableContext, arrayMove, rectSortingStrategy } from "@dnd-kit/sortable";
import { useSortableItem } from "@/lib/use-sortable-item";
import { GripVertical } from "lucide-react";
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

/** Moves one item by a number of places (keyboard). */
const MoveBy = createContext<((id: string, delta: number) => void) | undefined>(undefined);

export function SortableArea({
  ids,
  onMove,
  disabled,
  children,
}: {
  ids: string[];
  /** Receives the full id list in its new order. */
  onMove: (next: string[]) => void;
  disabled?: boolean;
  children: ReactNode;
}) {
  const t = useT();
  const [said, setSaid] = useState("");
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
    useSensor(TouchSensor, { activationConstraint: { delay: 180, tolerance: 6 } }),
  );
  const position = (id: string | number) => ids.indexOf(String(id)) + 1;
  function end(event: DragEndEvent) {
    const { active, over } = event;
    if (!over || active.id === over.id) return;
    onMove(arrayMove(ids, ids.indexOf(String(active.id)), ids.indexOf(String(over.id))));
  }
  function moveBy(id: string, delta: number) {
    const from = ids.indexOf(id),
      to = from + delta;
    if (disabled || from < 0 || to < 0 || to >= ids.length) return;
    onMove(arrayMove(ids, from, to));
    setSaid(t("dragDropped").replace("{n}", String(to + 1)));
  }
  return (
    <MoveBy.Provider value={moveBy}>
      <DndContext
        sensors={sensors}
        collisionDetection={closestCorners}
        onDragEnd={end}
        accessibility={{
          screenReaderInstructions: { draggable: t("dragInstructions") },
          announcements: {
            onDragStart: ({ active }) => t("dragPicked").replace("{n}", String(position(active.id))),
            onDragOver: ({ over }) => (over ? t("dragOver").replace("{n}", String(position(over.id))) : ""),
            onDragEnd: ({ over }) => (over ? t("dragDropped").replace("{n}", String(position(over.id))) : t("dragCancelled")),
            onDragCancel: () => t("dragCancelled"),
          },
        }}
      >
        <SortableContext items={ids} strategy={rectSortingStrategy} disabled={disabled}>
          {children}
        </SortableContext>
      </DndContext>
      <span className="sr-only" role="status" aria-live="polite">
        {said}
      </span>
    </MoveBy.Provider>
  );
}

export function DragHandle({
  handle,
  label,
  className,
}: {
  handle: ReturnType<typeof useSortableItem>["handle"];
  label: string;
  className?: string;
}) {
  const t = useT();
  const moveBy = useContext(MoveBy);
  const { id, ...props } = handle;
  function key(event: KeyboardEvent<HTMLButtonElement>) {
    const rtl = getComputedStyle(event.currentTarget).direction === "rtl";
    const delta =
      event.key === "ArrowUp" || event.key === (rtl ? "ArrowRight" : "ArrowLeft")
        ? -1
        : event.key === "ArrowDown" || event.key === (rtl ? "ArrowLeft" : "ArrowRight")
          ? 1
          : 0;
    if (!delta || !moveBy) return;
    event.preventDefault();
    moveBy(id, delta);
    // The same button moves with its item; keep it in view.
    const button = event.currentTarget;
    requestAnimationFrame(() => button.scrollIntoView({ block: "nearest" }));
  }
  return (
    <button
      type="button"
      {...props}
      onKeyDown={key}
      aria-label={`${t("dragHandle")}: ${label}`}
      className={cn("drag-handle", className)}
    >
      <GripVertical aria-hidden />
    </button>
  );
}

/** Render-prop wrapper so list markup (cards, table rows) stays inline. */
export function SortableItem({
  id,
  children,
}: {
  id: string;
  children: (item: ReturnType<typeof useSortableItem>) => ReactNode;
}) {
  return children(useSortableItem(id));
}
