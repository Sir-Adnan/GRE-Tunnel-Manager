// Pure decisions behind the touch gestures (bottom-sheet drag, card swipe), so
// thresholds are tested without a browser. Distances are CSS pixels and
// velocities are pixels per millisecond.

/** Movement below this many pixels is a tap, not a gesture. */
export const gestureSlop = 8;

/**
 * Which way a touch is going once it has moved past the slop: "x" for a swipe,
 * "y" for a scroll, undefined while it is still too short to tell. A diagonal
 * leans to scrolling so a list never feels sticky.
 */
export function lockAxis(dx: number, dy: number): "x" | "y" | undefined {
  const ax = Math.abs(dx),
    ay = Math.abs(dy);
  if (Math.max(ax, ay) < gestureSlop) return undefined;
  return ax > ay * 1.2 ? "x" : "y";
}

/** A sheet dragged down closes past a quarter of its height (at most 120 px) or on a quick flick. */
export function sheetShouldClose(dy: number, velocity: number, height: number) {
  if (dy <= 0) return false;
  return dy > Math.min(120, height / 4) || (velocity > 0.6 && dy > 24);
}

/** Pulling a sheet up is resisted so it cannot leave the screen edge. */
export function sheetOffset(dy: number) {
  return dy >= 0 ? dy : -Math.sqrt(-dy) * 2;
}

export type SwipeSide = "start" | "end" | "none";

/**
 * Where a swiped card rests. `offset` is measured toward the reading end
 * (positive reveals the actions at the start edge, negative the actions at the
 * end edge), so callers flip the sign in right-to-left pages. A card opens past
 * half of the revealed width or on a flick in that direction, and an open card
 * closes when moved back the same way.
 */
export function swipeSettle(
  offset: number,
  velocity: number,
  widths: { start: number; end: number },
): SwipeSide {
  const flick = 0.5;
  if (offset < 0 && widths.end > 0)
    return velocity <= flick && (-offset > widths.end / 2 || velocity < -flick)
      ? "end"
      : "none";
  if (offset > 0 && widths.start > 0)
    return velocity >= -flick && (offset > widths.start / 2 || velocity > flick)
      ? "start"
      : "none";
  return "none";
}

/** Beyond the revealed actions the card follows the finger with resistance. */
export function swipeOffset(
  offset: number,
  widths: { start: number; end: number },
) {
  const limit = offset < 0 ? widths.end : widths.start;
  if (limit === 0) return 0;
  const over = Math.abs(offset) - limit;
  const value = over > 0 ? limit + Math.sqrt(over) * 3 : Math.abs(offset);
  return Math.sign(offset) * value;
}

/**
 * Whether the phone's bottom bar should be out of the way after a scroll of
 * `dy` pixels ending at `y`: hidden while reading down, back on any clear move
 * up, near the top and at the very end of the page.
 */
export function barHidden(
  hidden: boolean,
  { y, dy, atEnd }: { y: number; dy: number; atEnd: boolean },
) {
  if (y < 64 || atEnd) return false;
  if (dy > 6) return true;
  if (dy < -6) return false;
  return hidden;
}

/** Keeps a gesture's pointer on one element; a pointer that is already gone is ignored. */
export function capturePointer(element: Element, pointerId: number) {
  try {
    element.setPointerCapture(pointerId);
  } catch {
    /* The pointer ended before the gesture locked in. */
  }
}
