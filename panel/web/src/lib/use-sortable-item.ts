// One sortable item's node ref, style and drag-handle props (see components/sortable).
import { createContext, useContext, type CSSProperties } from "react";
import { useSortable } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";

/** Ref, style and handle props for one sortable item. */
export function useSortableItem(id: string) {
  const { attributes, listeners, setNodeRef, setActivatorNodeRef, transform, transition, isDragging } = useSortable({ id });
  const style: CSSProperties = {
    transform: CSS.Translate.toString(transform),
    transition,
    position: "relative",
    zIndex: isDragging ? 5 : undefined,
  };
  return {
    setNodeRef,
    style,
    dragging: isDragging,
    handle: { ref: setActivatorNodeRef, id, ...attributes, ...listeners },
    /** Spread on a whole row so a touch press and hold anywhere picks it up. */
    press: listeners,
  };
}

/** Moves one item of the surrounding SortableArea by a number of places. */
export const MoveBy = createContext<
  ((id: string, delta: number) => void) | undefined
>(undefined);

/** For move buttons (components/ReorderList) and the handle's arrow keys. */
export function useMoveBy() {
  return useContext(MoveBy);
}
