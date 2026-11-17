import { useState, type ComponentProps, type ReactNode } from "react";
import {
  ArrowUpRight,
  FileUp,
  Check,
  CircleAlert,
  Copy,
  Network,
  Plus,
  Route,
  Workflow,
} from "lucide-react";
import { useCopyText } from "@/lib/use-copy-text";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Field, FieldLabel } from "@/components/ui/field";
import { HelpTip } from "@/components/help";
import { Input } from "@/components/ui/input";
import {
  NativeSelect,
  NativeSelectOption,
} from "@/components/ui/native-select";
import {
  Empty,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
  EmptyDescription,
  EmptyContent,
} from "@/components/ui/empty";
import { useT } from "@/lib/i18n";
import { useFieldError } from "@/lib/field-errors";

export function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <span className="brand-mark">
        <Network className="size-5" />
      </span>
      {!compact && (
        <span className="flex flex-col">
          <strong className="text-sm font-semibold tracking-tight" dir="ltr">
            TUNNEL<span className="text-primary">.</span>
          </strong>
          <span
            className="text-[10px] tracking-widest text-muted-foreground"
            dir="ltr"
          >
            MANAGER
          </span>
        </span>
      )}
    </div>
  );
}
/** One glyph per engine family, used wherever a connection is listed. */
export function EngineGlyph({
  engine,
  className = "size-4",
}: {
  engine: string;
  className?: string;
}) {
  const Icon =
    engine === "haproxy" ? Workflow : engine === "realm" ? Network : Route;
  return <Icon className={className} aria-hidden />;
}
/** Runtime state in words. A tone (lib/connection-tone) colors the dot and text for connection lists. */
export function Status({
  value = "unknown",
  tone,
}: {
  value?: string;
  tone?: string;
}) {
  const t = useT();
  const active = value === "active";
  return (
    <Badge
      variant={active ? "secondary" : "outline"}
      className="status-badge gap-1.5"
      data-tone={tone}
    >
      <span className={active ? "status-dot is-active" : "status-dot"} />
      {t(value)}
    </Badge>
  );
}
/** The label row every field shares: one height with or without help, so
 * fields side by side keep their inputs on one line. */
function FieldHead({
  id,
  label,
  help,
  optional,
  hidden,
}: {
  id?: string;
  label: string;
  help?: string;
  optional?: boolean;
  hidden?: boolean;
}) {
  const t = useT();
  return (
    <div className={hidden ? "sr-only" : "field-label-row"}>
      <FieldLabel htmlFor={id}>
        {label}
        {optional && <span className="field-optional">{t("optional")}</span>}
      </FieldLabel>
      {help && <HelpTip label={`${label} · ?`}>{help}</HelpTip>}
    </div>
  );
}
/** A hint under the field, replaced by the error when there is one. */
function FieldNote({
  id,
  error,
  description,
}: {
  id: string;
  error: string;
  description?: ReactNode;
}) {
  if (error)
    return (
      <p id={id} className="field-error" role="alert">
        <CircleAlert aria-hidden />
        <span>{error}</span>
      </p>
    );
  if (!description) return null;
  return (
    <p id={id} className="field-hint">
      {description}
    </p>
  );
}
export function TextField({
  label,
  help,
  optional,
  description,
  error,
  ...props
}: {
  label: string;
  help?: string;
  /** Marks the label "Optional" in a quieter weight. */
  optional?: boolean;
  /** A short hint under the input. */
  description?: ReactNode;
  /** Shown instead of the hint; falls back to the form's error for this id. */
  error?: string;
} & ComponentProps<typeof Input>) {
  const formError = useFieldError(props.id);
  const message = error || formError;
  const noteId = `${props.id}-note`;
  const noted = Boolean(message || description);
  return (
    <Field data-invalid={message ? true : undefined} data-inline-error>
      <FieldHead id={props.id} label={label} help={help} optional={optional} />
      <Input
        {...props}
        aria-invalid={message ? true : props["aria-invalid"]}
        aria-describedby={noted ? noteId : props["aria-describedby"]}
      />
      <FieldNote id={noteId} error={message} description={description} />
    </Field>
  );
}
/**
 * A file picker that matches the text inputs beside it: same label row and
 * height, a localized button and the chosen name instead of the browser's
 * own "Choose File / No file chosen". A file can also be dropped on it.
 */
export function FileField({
  id,
  label,
  help,
  accept,
  disabled,
  required,
  fileName,
  description,
  error,
  onFile,
}: {
  id: string;
  label: string;
  help?: string;
  accept?: string;
  disabled?: boolean;
  required?: boolean;
  /** The chosen file's name, kept by the caller (cleared on reset). */
  fileName?: string;
  description?: ReactNode;
  error?: string;
  /** Receives the file; the input is cleared after, so the same file can be chosen again. */
  onFile: (file: File) => void;
}) {
  const t = useT();
  const formError = useFieldError(id);
  const message = error || formError;
  const [dragging, setDragging] = useState(false);
  const noteId = `${id}-note`;
  return (
    <Field data-invalid={message ? true : undefined} data-inline-error>
      <FieldHead id={id} label={label} help={help} />
      <label
        className="file-field"
        data-dragging={dragging || undefined}
        data-disabled={disabled || undefined}
        data-chosen={fileName ? true : undefined}
        onDragOver={(e) => {
          if (disabled) return;
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const file = e.dataTransfer.files?.[0];
          if (file && !disabled) onFile(file);
        }}
      >
        <input
          id={id}
          type="file"
          className="sr-only"
          accept={accept}
          disabled={disabled}
          required={required && !fileName}
          aria-invalid={message ? true : undefined}
          aria-describedby={message || description ? noteId : undefined}
          onChange={(e) => {
            const file = e.target.files?.[0];
            e.target.value = "";
            if (file) onFile(file);
          }}
        />
        <FileUp aria-hidden className="file-field-icon" />
        <span className="file-field-name">
          {fileName ? <bdi>{fileName}</bdi> : t("noFileChosen")}
        </span>
        <span className="file-field-button" aria-hidden>
          {fileName ? t("replaceFile") : t("chooseFile")}
        </span>
      </label>
      <FieldNote id={noteId} error={message} description={description} />
    </Field>
  );
}
export function Choice({
  label,
  value,
  onChange,
  choices,
  id,
  help,
  description,
  labelHidden = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  choices: { value: string; label: string; disabled?: boolean }[];
  id: string;
  help?: string;
  /** A short hint under the select. */
  description?: ReactNode;
  labelHidden?: boolean;
}) {
  const message = useFieldError(id);
  const noteId = `${id}-note`;
  return (
    <Field data-invalid={message ? true : undefined} data-inline-error>
      <FieldHead id={id} label={label} help={help} hidden={labelHidden} />
      <NativeSelect
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="w-full"
        aria-invalid={message ? true : undefined}
        aria-describedby={message || description ? noteId : undefined}
      >
        {choices.map((option) => (
          <NativeSelectOption
            key={option.value}
            value={option.value}
            disabled={option.disabled}
          >
            {option.label}
          </NativeSelectOption>
        ))}
      </NativeSelect>
      <FieldNote id={noteId} error={message} description={description} />
    </Field>
  );
}
export function Address({
  children,
  notify,
}: {
  children: string;
  notify?: (message: string) => void;
}) {
  const t = useT();
  const { status, copy } = useCopyText(children);
  return (
    <span className="inline-flex min-w-0 max-w-full flex-wrap items-center gap-1">
      <Button
        type="button"
        size="sm"
        variant="ghost"
        className="max-w-full min-w-0 justify-start"
        title={`${t("copy")}: ${children}`}
        onClick={() =>
          void copy().then((ok) => notify?.(t(ok ? "copied" : "copyFailed")))
        }
      >
        <Badge variant="outline">
          {children.includes(":") ? "IPv6" : "IPv4"}
        </Badge>
        <code className="max-w-64 truncate text-xs" dir="ltr">
          {children}
        </code>
        {status === "copied" ? (
          <Check data-icon="inline-end" />
        ) : (
          <Copy data-icon="inline-end" />
        )}
      </Button>
      <span
        role="status"
        className={
          status === "copyFailed" ? "text-xs text-muted-foreground" : "sr-only"
        }
      >
        {status && t(status)}
      </span>
    </span>
  );
}
export function Blank({
  onAdd,
  filtered = false,
  onReset,
}: {
  onAdd: () => void;
  filtered?: boolean;
  onReset?: () => void;
}) {
  const t = useT();
  return (
    <Empty className="min-h-64">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Network />
        </EmptyMedia>
        <EmptyTitle>{t(filtered ? "noMatch" : "emptyTitle")}</EmptyTitle>
        <EmptyDescription>
          {t(filtered ? "noMatchesHelp" : "emptyDesc")}
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button onClick={filtered && onReset ? onReset : onAdd}>
          <Plus data-icon="inline-start" />
          {t(filtered && onReset ? "clearFilters" : "newConnection")}
        </Button>
      </EmptyContent>
    </Empty>
  );
}
export function PageTitle({
  title,
  description,
  action,
  heading: Heading = "h1",
}: {
  heading?: "h1" | "h2";
  title: string;
  description: string;
  action?: ReactNode;
}) {
  const t = useT();
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div className="flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <Heading
            className={
              Heading === "h1"
                ? "page-title"
                : "text-lg font-semibold tracking-tight"
            }
          >
            {title}
          </Heading>
          {description && (
            <HelpTip label={`${title} · ${t("help")}`}>{description}</HelpTip>
          )}
        </div>
      </div>
      {action}
    </div>
  );
}
export function SectionLink({
  children,
  onClick,
}: {
  children: ReactNode;
  onClick: () => void;
}) {
  return (
    <Button variant="ghost" onClick={onClick}>
      {children}
      <ArrowUpRight data-icon="inline-end" />
    </Button>
  );
}
