import {
  useContext,
  useEffect,
  useRef,
  useState,
  type CSSProperties,
  type PointerEvent,
  type ReactNode,
  type Ref,
} from "react";
import {
  capturePointer,
  lockAxis,
  swipeOffset,
  swipeSettle,
  type SwipeSide,
} from "@/lib/gesture";
import { LocaleContext } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export type SwipeAction = {
  id: string;
  label: string;
  icon: ReactNode;
  tone?: "primary" | "warn" | "ok" | "muted";
  onSelect: () => void;
};

/** Where a swipe may not start: controls that own their own drag or tap. */
const ownGesture =
  ".drag-handle,input,textarea,select,[role=slider],[data-no-swipe]";

type Track = {
  id: number;
  x: number;
  y: number;
  t: number;
  base: number;
  offset: number;
  v: number;
  axis?: "x" | "y";
  widths: { start: number; end: number };
};

/**
 * A card that slides sideways under a finger to show quick actions, like a
 * phone's mail list. `end` actions appear when the card moves toward the
 * reading start (left in English, right in Persian); `start` actions the other
 * way. Only touch starts a swipe and every action stays reachable from the
 * card's own buttons, so mouse, keyboard and screen-reader use is unchanged:
 * the revealed buttons are hidden from assistive technology.
 */
export function SwipeActions({
  start = [],
  end = [],
  children,
  className,
  style,
  rootRef,
  disabled,
}: {
  start?: SwipeAction[];
  end?: SwipeAction[];
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
  rootRef?: Ref<HTMLDivElement>;
  /** No swipe starts (selection mode); an open card closes. */
  disabled?: boolean;
}) {
  // `rest` is the open card's offset toward the reading end; `live` follows the finger.
  const [state, setState] = useState<{
    open: SwipeSide;
    rest: number;
  }>({ open: "none", rest: 0 });
  const { open, rest } = disabled ? { open: "none" as const, rest: 0 } : state;
  const close = () => setState({ open: "none", rest: 0 });
  const [live, setLive] = useState<number>();
  const sign = useContext(LocaleContext) === "fa" ? -1 : 1;
  const box = useRef<HTMLDivElement>(null);
  const track = useRef<Track | undefined>(undefined);
  const swallowClick = useRef(false);
  const widthOf = (side: "start" | "end") =>
    box.current?.querySelector<HTMLElement>(`.swipe-actions.is-${side}`)
      ?.offsetWidth ?? 0;
  // A swipe ends with a click on whatever was under the finger; drop that one click.
  const swallowNextClick = () => {
    swallowClick.current = true;
    setTimeout(() => (swallowClick.current = false), 400);
  };

  // An open card closes when anything else on the page is touched.
  useEffect(() => {
    if (open === "none") return;
    const outside = (event: globalThis.PointerEvent) => {
      if (!box.current?.contains(event.target as Node))
        setState({ open: "none", rest: 0 });
    };
    document.addEventListener("pointerdown", outside, true);
    return () => document.removeEventListener("pointerdown", outside, true);
  }, [open]);

  function down(event: PointerEvent<HTMLDivElement>) {
    if (event.pointerType !== "touch" || disabled) return;
    const target = event.target as HTMLElement;
    if (target.closest(ownGesture) || target.closest(".swipe-actions")) return;
    track.current = {
      id: event.pointerId,
      x: event.clientX,
      y: event.clientY,
      t: event.timeStamp,
      base: rest,
      offset: rest,
      v: 0,
      widths: { start: widthOf("start"), end: widthOf("end") },
    };
  }
  function move(event: PointerEvent<HTMLDivElement>) {
    const d = track.current;
    if (!d || d.id !== event.pointerId) return;
    const dx = (event.clientX - d.x) * sign;
    if (!d.axis) {
      d.axis = lockAxis(dx, event.clientY - d.y);
      if (d.axis === "y") {
        track.current = undefined;
        return;
      }
      if (!d.axis) return;
      capturePointer(event.currentTarget, event.pointerId);
    }
    const offset = swipeOffset(d.base + dx, d.widths);
    d.v = (offset - d.offset) / Math.max(1, event.timeStamp - d.t);
    d.offset = offset;
    d.t = event.timeStamp;
    setLive(offset);
  }
  function up(event: PointerEvent<HTMLDivElement>) {
    const d = track.current;
    track.current = undefined;
    if (!d || d.id !== event.pointerId) return;
    if (!d.axis) {
      // A tap on an open card closes it instead of activating what is under it.
      if (open !== "none") {
        swallowNextClick();
        close();
      }
      return;
    }
    swallowNextClick();
    const next = swipeSettle(d.offset, d.v, d.widths);
    if (next !== "none" && next !== open) navigator.vibrate?.(8);
    setState({
      open: next,
      rest:
        next === "end" ? -d.widths.end : next === "start" ? d.widths.start : 0,
    });
    setLive(undefined);
  }
  const shift = sign * (live ?? rest);
  const button = (action: SwipeAction) => (
    <button
      key={action.id}
      type="button"
      tabIndex={-1}
      className="swipe-action"
      data-tone={action.tone ?? "muted"}
      onClick={() => {
        close();
        action.onSelect();
      }}
    >
      {action.icon}
      <span>{action.label}</span>
    </button>
  );
  return (
    <div
      ref={rootRef}
      style={style}
      className={cn("swipe-row", className)}
      data-open={open === "none" ? undefined : open}
      data-swiping={live === undefined ? undefined : ""}
    >
      <div ref={box} className="swipe-box">
        {start.length > 0 && (
          <div className="swipe-actions is-start" aria-hidden>
            {start.map(button)}
          </div>
        )}
        {end.length > 0 && (
          <div className="swipe-actions is-end" aria-hidden>
            {end.map(button)}
          </div>
        )}
        <div
          className="swipe-surface"
          data-moving={live === undefined ? undefined : ""}
          style={{ translate: shift ? `${shift}px 0` : undefined }}
          onPointerDown={down}
          onPointerMove={move}
          onPointerUp={up}
          onPointerCancel={() => {
            track.current = undefined;
            setLive(undefined);
          }}
          onClickCapture={(event) => {
            if (!swallowClick.current) return;
            swallowClick.current = false;
            event.preventDefault();
            event.stopPropagation();
          }}
        >
          {children}
        </div>
      </div>
    </div>
  );
}
