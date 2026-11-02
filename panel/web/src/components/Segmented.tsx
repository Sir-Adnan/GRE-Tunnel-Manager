import type { KeyboardEvent, ReactNode } from "react";
import { cn } from "@/lib/utils";

export type SegmentedOption = {
  value: string;
  label: ReactNode;
  count?: string;
  icon?: ReactNode;
};

/** A compact single-choice filter (radio semantics), scrollable on narrow screens. */
export function Segmented({
  label,
  value,
  options,
  onChange,
  className,
}: {
  label: string;
  value: string;
  options: SegmentedOption[];
  onChange: (value: string) => void;
  className?: string;
}) {
  // Radio-group keyboard model: one tab stop, arrows move and select (mirrored in RTL), Home/End jump.
  function move(event: KeyboardEvent<HTMLDivElement>) {
    const index = options.findIndex((option) => option.value === value);
    const rtl = getComputedStyle(event.currentTarget).direction === "rtl";
    const step =
      event.key === "ArrowDown" ||
      event.key === (rtl ? "ArrowLeft" : "ArrowRight")
        ? 1
        : event.key === "ArrowUp" ||
            event.key === (rtl ? "ArrowRight" : "ArrowLeft")
          ? -1
          : 0;
    const next =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? options.length - 1
          : step
            ? (index + step + options.length) % options.length
            : -1;
    if (next < 0) return;
    event.preventDefault();
    onChange(options[next].value);
    event.currentTarget
      .querySelectorAll<HTMLButtonElement>('[role="radio"]')
      [next]?.focus();
  }
  return (
    <div
      onKeyDown={move}
      role="radiogroup"
      aria-label={label}
      className={cn("segmented", className)}
    >
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          role="radio"
          aria-checked={option.value === value}
          tabIndex={option.value === value ? 0 : -1}
          data-state={option.value === value ? "on" : "off"}
          onClick={() => onChange(option.value)}
        >
          {option.icon}
          <span className="truncate">{option.label}</span>
          {option.count !== undefined && (
            <span className="segmented-count">{option.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}
