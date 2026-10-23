import type { ComponentProps, ReactNode } from "react";
import { ArrowUpRight, Copy, Network, Plus } from "lucide-react";
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
export function Status({ value = "unknown" }: { value?: string }) {
  const t = useT();
  const active = value === "active";
  return (
    <Badge variant={active ? "secondary" : "outline"} className="gap-1.5">
      <span className={active ? "status-dot is-active" : "status-dot"} />
      {t(value)}
    </Badge>
  );
}
export function TextField({
  label,
  help,
  ...props
}: { label: string; help?: string } & ComponentProps<typeof Input>) {
  return (
    <Field>
      <div className="flex items-center gap-1">
        <FieldLabel htmlFor={props.id}>{label}</FieldLabel>
        {help && <HelpTip label={`${label} · ?`}>{help}</HelpTip>}
      </div>
      <Input {...props} />
    </Field>
  );
}
export function Choice({
  label,
  value,
  onChange,
  choices,
  id,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  choices: { value: string; label: string; disabled?: boolean }[];
  id: string;
}) {
  return (
    <Field>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <NativeSelect
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="w-full"
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
  return (
    <Button
      size="sm"
      variant="ghost"
      title={t("copy")}
      onClick={() =>
        navigator.clipboard
          .writeText(children)
          .then(() => notify?.(t("copied")))
          .catch(() => notify?.(children))
      }
    >
      <code className="max-w-64 truncate" dir="ltr">
        {children}
      </code>
      <Copy data-icon="inline-end" />
    </Button>
  );
}
export function Blank({
  onAdd,
  filtered = false,
}: {
  onAdd: () => void;
  filtered?: boolean;
}) {
  const t = useT();
  return (
    <Empty className="min-h-64">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Network />
        </EmptyMedia>
        <EmptyTitle>{t(filtered ? "noMatch" : "emptyTitle")}</EmptyTitle>
        <EmptyDescription>{t("emptyDesc")}</EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button onClick={onAdd}>
          <Plus data-icon="inline-start" />
          {t("newConnection")}
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
