import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * A dashboard figure: label, one value, a detail line and an optional trend.
 * With onClick it is a button that opens the page behind the figure.
 */
export function Kpi({
  icon: Icon,
  label,
  value,
  detail,
  tone,
  trend,
  onClick,
}: {
  icon: LucideIcon;
  label: string;
  value: ReactNode;
  detail: ReactNode;
  tone?: "alert" | "ok" | "muted";
  /** A small chart under the value (live traffic). */
  trend?: ReactNode;
  onClick?: () => void;
}) {
  const body = (
    <>
      <span className="kpi-label">
        <Icon className="size-4" />
        {label}
      </span>
      <span className="kpi-value">
        <bdi>{value}</bdi>
      </span>
      <span className="kpi-detail">
        <bdi>{detail}</bdi>
      </span>
      {trend && <span className="kpi-trend">{trend}</span>}
    </>
  );
  const className = cn("kpi", tone && `is-${tone}`);
  return onClick ? (
    <button type="button" className={className} onClick={onClick}>
      {body}
    </button>
  ) : (
    <div className={className}>{body}</div>
  );
}
