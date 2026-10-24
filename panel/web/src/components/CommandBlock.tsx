import { useState } from "react";
import { Copy, Check } from "lucide-react";
import { ActionButton } from "@/components/help";
import { useT } from "@/lib/i18n";

/** A command is a block with intrinsic height, never a shrinking flex item. */
export function CommandBlock({ text }: { text: string }) {
  const t = useT();
  const [status, setStatus] = useState("");
  return (
    <div className="flex min-w-0 shrink-0 flex-col gap-2 rounded-lg border bg-background p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs text-muted-foreground">{t("command")}</span>
        <ActionButton
          type="button"
          variant="ghost"
          size="icon-sm"
          label={t("copyCommand")}
          onClick={() => {
            if (!navigator.clipboard) {
              setStatus("copyManually");
              return;
            }
            void navigator.clipboard
              .writeText(text)
              .then(() => setStatus("copied"))
              .catch(() => setStatus("copyManually"));
          }}
        >
          {status === "copied" ? <Check /> : <Copy />}
        </ActionButton>
      </div>
      <pre
        dir="ltr"
        tabIndex={0}
        className="min-w-0 whitespace-pre-wrap text-start text-xs leading-6 [overflow-wrap:anywhere]"
        aria-label={t("command")}
      >
        <code>{text}</code>
      </pre>
      {status && (
        <p className="text-xs text-muted-foreground" role="status">
          {t(status)}
        </p>
      )}
    </div>
  );
}
