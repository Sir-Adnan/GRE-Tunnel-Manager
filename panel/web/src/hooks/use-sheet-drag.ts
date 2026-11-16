import { useRef, type PointerEvent } from "react";
import {
  capturePointer,
  gestureSlop,
  sheetOffset,
  sheetShouldClose,
} from "@/lib/gesture";

type Drag = {
  id: number;
  y: number;
  t: number;
  dy: number;
  v: number;
  on: boolean;
};

/**
 * Pointer handlers for a bottom sheet's grabber: the sheet follows a downward
 * drag and closes past the threshold in lib/gesture. The offset uses the CSS
 * `translate` property so the closing animation (a transform) continues from
 * where the finger let go instead of jumping back first. `close` goes through
 * the dialog's own onOpenChange, so a dialog that refuses to close (busy) just
 * springs back.
 */
export function useSheetDrag(close: () => void) {
  const drag = useRef<Drag | undefined>(undefined);
  const sheetOf = (grabber: HTMLElement) =>
    grabber.closest<HTMLElement>("[data-slot$='-content']");

  function onPointerDown(event: PointerEvent<HTMLElement>) {
    if (event.button !== 0) return;
    drag.current = {
      id: event.pointerId,
      y: event.clientY,
      t: event.timeStamp,
      dy: 0,
      v: 0,
      on: false,
    };
  }
  function onPointerMove(event: PointerEvent<HTMLElement>) {
    const d = drag.current,
      sheet = sheetOf(event.currentTarget);
    if (!d || d.id !== event.pointerId || !sheet) return;
    const dy = event.clientY - d.y;
    if (!d.on) {
      if (Math.abs(dy) < gestureSlop) return;
      d.on = true;
      capturePointer(event.currentTarget, event.pointerId);
      sheet.dataset.dragging = "";
    }
    d.v = (dy - d.dy) / Math.max(1, event.timeStamp - d.t);
    d.dy = dy;
    d.t = event.timeStamp;
    sheet.style.translate = `0 ${sheetOffset(dy)}px`;
  }
  function onPointerEnd(event: PointerEvent<HTMLElement>) {
    const d = drag.current,
      sheet = sheetOf(event.currentTarget);
    drag.current = undefined;
    if (!d?.on || !sheet) return;
    delete sheet.dataset.dragging;
    if (!sheetShouldClose(d.dy, d.v, sheet.offsetHeight)) {
      sheet.style.translate = "";
      return;
    }
    close();
    // Still open: the dialog declined to close (for example while saving).
    setTimeout(() => {
      if (sheet.dataset.state === "open") sheet.style.translate = "";
    }, 80);
  }
  return {
    onPointerDown,
    onPointerMove,
    onPointerUp: onPointerEnd,
    onPointerCancel: onPointerEnd,
  };
}
