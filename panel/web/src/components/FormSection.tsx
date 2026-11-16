import { useId, type ReactNode } from "react";

/**
 * One titled card of a form: an icon, a short title and one line on what the
 * section decides, then its fields. Long forms read as a few small questions
 * instead of one wall of inputs; every section shares the same rhythm.
 */
export function FormSection({
  icon,
  title,
  description,
  action,
  children,
  className,
}: {
  icon?: ReactNode;
  title: string;
  description?: ReactNode;
  /** A small control at the end of the header, such as a link. */
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  const id = useId();
  return (
    <section
      className={className ? `form-section ${className}` : "form-section"}
      aria-labelledby={id}
    >
      <header className="form-section-head">
        {icon && (
          <span className="form-section-icon" aria-hidden>
            {icon}
          </span>
        )}
        <div className="min-w-0 flex-1">
          <h3 id={id} className="form-section-title">
            {title}
          </h3>
          {description && <p className="form-section-desc">{description}</p>}
        </div>
        {action}
      </header>
      <div className="form-section-body">{children}</div>
    </section>
  );
}
