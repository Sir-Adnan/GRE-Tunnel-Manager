// One sortable item's node ref, style and drag-handle props (see components/sortable).
import type { CSSProperties } from "react";
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
  };
}
