import { sparkPath } from "@/lib/sparkline";

/** A decorative trend line beside a reading; the reading itself carries the value for assistive tech. */
export function Sparkline({
  values,
  max,
  className,
}: {
  values: readonly number[];
  max?: number;
  className?: string;
}) {
  const path = sparkPath(values, 58, 20, max);
  return (
    <svg
      className={className ? `sparkline ${className}` : "sparkline"}
      viewBox="0 0 58 20"
      preserveAspectRatio="none"
      aria-hidden
    >
      {path && <path d={path} />}
    </svg>
  );
}
