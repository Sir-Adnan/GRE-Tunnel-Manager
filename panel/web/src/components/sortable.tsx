// Drag-and-drop reordering for a vertical list. The handle drags at once with
// a mouse, pen or finger; on touch, a press and hold anywhere a row spreads
// `item.press` also picks it up (a short vibration confirms), so a swipe
// still scrolls. With the keyboard, focus the handle and press an arrow key
// to move the item one place (mirrored in right-to-left). Buttons and fields
// in a row keep working and screen readers hear each move.
import {
  useContext,
  useState,
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
  type ReactNode,
  type TouchEvent as ReactTouchEvent,
} from "react";
import {
  DndContext,
  PointerSensor,
  TouchSensor,
  closestCenter,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragOverEvent,
  type DragStartEvent,
} from "@dnd-kit/core";
import {
  SortableContext,
  arrayMove,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { MoveBy, useSortableItem } from "@/lib/use-sortable-item";
import { GripVertical } from "lucide-react";
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

// React events bubble out of portals (a row's menu sheet); only presses on
// the row itself count.
const inside = (row: EventTarget, target: EventTarget | null) =>
  row instanceof Node && target instanceof Node && row.contains(target);
const onHandle = (target: EventTarget | null) =>
  target instanceof Element && Boolean(target.closest(".drag-handle"));
// A press on a control (a menu button, a field) is that control's own.
const onControl = (target: EventTarget | null) =>
  target instanceof Element &&
  Boolean(
    target.closest(
      "button:not(.drag-handle),a,input,select,textarea,[role=menuitem]",
    ),
  );

/** Mouse, pen or finger on the handle: starts after a few pixels. */
class HandleSensor extends PointerSensor {
  static activators = [
    {
      eventName: "onPointerDown" as const,
      handler: ({ nativeEvent, currentTarget }: ReactPointerEvent) =>
        inside(currentTarget, nativeEvent.target) &&
        nativeEvent.isPrimary &&
        nativeEvent.button === 0 &&
        onHandle(nativeEvent.target),
    },
  ];
}

/** A finger held on the rest of a row: starts after a short press. */
class PressSensor extends TouchSensor {
  static activators = [
    {
      eventName: "onTouchStart" as const,
      handler: ({ nativeEvent, currentTarget }: ReactTouchEvent) =>
        inside(currentTarget, nativeEvent.target) &&
        nativeEvent.touches.length === 1 &&
        !onHandle(nativeEvent.target) &&
        !onControl(nativeEvent.target),
    },
  ];
}

export function SortableArea({
  ids,
  onMove,
  onPreview,
  disabled,
  children,
}: {
  ids: string[];
  /** Receives the full id list in its new order. */
  onMove: (next: string[]) => void;
  /** The order the list would have if dropped now; null when no drag runs. */
  onPreview?: (next: string[] | null) => void;
  disabled?: boolean;
  children: ReactNode;
}) {
  const t = useT();
  const [said, setSaid] = useState("");
  const sensors = useSensors(
    useSensor(HandleSensor, { activationConstraint: { distance: 4 } }),
    useSensor(PressSensor, {
      activationConstraint: { delay: 260, tolerance: 8 },
    }),
  );
  const position = (id: string | number) => ids.indexOf(String(id)) + 1;
  function start(event: DragStartEvent) {
    if (event.activatorEvent.type === "touchstart") navigator.vibrate?.(12);
  }
  function over({ active, over }: DragOverEvent) {
    if (!onPreview || !over) return;
    onPreview(
      arrayMove(
        ids,
        ids.indexOf(String(active.id)),
        ids.indexOf(String(over.id)),
      ),
    );
  }
  function end(event: DragEndEvent) {
    onPreview?.(null);
    const { active, over } = event;
    if (!over || active.id === over.id) return;
    onMove(
      arrayMove(
        ids,
        ids.indexOf(String(active.id)),
        ids.indexOf(String(over.id)),
      ),
    );
  }
  function moveBy(id: string, delta: number) {
    const from = ids.indexOf(id),
      to = Math.min(ids.length - 1, Math.max(0, from + delta));
    if (disabled || from < 0 || to === from) return;
    onMove(arrayMove(ids, from, to));
    setSaid(t("dragDropped").replace("{n}", String(to + 1)));
  }
  return (
    <MoveBy.Provider value={moveBy}>
      <DndContext
        sensors={sensors}
        collisionDetection={closestCenter}
        onDragStart={start}
        onDragOver={over}
        onDragEnd={end}
        onDragCancel={() => onPreview?.(null)}
        accessibility={{
          screenReaderInstructions: { draggable: t("dragInstructions") },
          announcements: {
            onDragStart: ({ active }) =>
              t("dragPicked").replace("{n}", String(position(active.id))),
            onDragOver: ({ over }) =>
              over
                ? t("dragOver").replace("{n}", String(position(over.id)))
                : "",
            onDragEnd: ({ over }) =>
              over
                ? t("dragDropped").replace("{n}", String(position(over.id)))
                : t("dragCancelled"),
            onDragCancel: () => t("dragCancelled"),
          },
        }}
      >
        <SortableContext
          items={ids}
          strategy={verticalListSortingStrategy}
          disabled={disabled}
        >
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
      event.key === "ArrowUp" ||
      event.key === (rtl ? "ArrowRight" : "ArrowLeft")
        ? -1
        : event.key === "ArrowDown" ||
            event.key === (rtl ? "ArrowLeft" : "ArrowRight")
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

/** Render-prop wrapper so list markup stays inline. */
export function SortableItem({
  id,
  children,
}: {
  id: string;
  children: (item: ReturnType<typeof useSortableItem>) => ReactNode;
}) {
  return children(useSortableItem(id));
}
