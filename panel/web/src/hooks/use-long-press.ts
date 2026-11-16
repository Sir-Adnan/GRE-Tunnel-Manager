// A touch long press (about half a second without moving), as on a phone's
// list: it starts selection mode. Mouse, pen and keyboard use visible buttons.
import { useEffect, useRef, type PointerEvent } from "react";
import { gestureSlop } from "@/lib/gesture";

export const longPressMs = 450;

/** Pointer and click handlers for an element; `press` runs once per long press. */
export function useLongPress(press: () => void, enabled = true) {
  const timer = useRef<number | undefined>(undefined);
  const start = useRef<{ x: number; y: number } | undefined>(undefined);
  const fired = useRef(false);
  const stop = () => {
    window.clearTimeout(timer.current);
    timer.current = undefined;
    start.current = undefined;
  };
  useEffect(() => stop, []);
  return {
    onPointerDown(event: PointerEvent<HTMLElement>) {
      fired.current = false;
      if (!enabled || event.pointerType !== "touch") return;
      start.current = { x: event.clientX, y: event.clientY };
      timer.current = window.setTimeout(() => {
        stop();
        fired.current = true;
        navigator.vibrate?.(12);
        press();
      }, longPressMs);
    },
    onPointerMove(event: PointerEvent<HTMLElement>) {
      const s = start.current;
      if (
        s &&
        Math.hypot(event.clientX - s.x, event.clientY - s.y) > gestureSlop
      )
        stop();
    },
    onPointerUp: stop,
    onPointerCancel: stop,
    // The press ends with a click on whatever was under the finger; drop it,
    // and the browser's own long-press menu with it.
    onClickCapture(event: { preventDefault(): void; stopPropagation(): void }) {
      if (!fired.current) return;
      fired.current = false;
      event.preventDefault();
      event.stopPropagation();
    },
    onContextMenu(event: { preventDefault(): void }) {
      if (start.current || fired.current) event.preventDefault();
    },
  };
}
