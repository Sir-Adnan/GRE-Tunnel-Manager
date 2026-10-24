import type { ComponentProps } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useCopyText } from "@/lib/use-copy-text";
import { useT } from "@/lib/i18n";

export function CopyButton({
  text,
  label,
  ...props
}: Omit<ComponentProps<typeof Button>, "onClick" | "children" | "asChild"> & {
  text: string;
  label: string;
}) {
  const t = useT();
  const { status, copy } = useCopyText(text);
  return (
    <span className="inline-flex max-w-full flex-wrap items-center gap-2">
      <Button
        type="button"
        variant="outline"
        {...props}
        onClick={() => void copy()}
      >
        {status === "copied" ? (
          <Check data-icon="inline-start" />
        ) : (
          <Copy data-icon="inline-start" />
        )}
        {status === "copied" ? t(status) : label}
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
