// Small presentational pieces of the Firewall page.

import { Check, Undo2 } from "lucide-react";
import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { useNow } from "@/features/operations/hooks";
import { useT } from "@/lib/i18n";
import { fill } from "./text";

export type Tone = "ok" | "warn" | "problem" | "muted";

/** A compact state label; color is never the only signal (text and dot). */
export function Pill({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className="fw-pill" data-tone={tone}>
      <span className="fw-pill-dot" aria-hidden />
      {children}
    </span>
  );
}

/** Port text such as "8000-8003/tcp", always left to right. */
export function PortText({
  port,
  protocol,
}: {
  port: string;
  protocol: string;
}) {
  return (
    <bdi dir="ltr" className="font-mono tabular-nums">
      {port}/{protocol}
    </bdi>
  );
}

/** The countdown of an unconfirmed change with Keep and Revert. */
export function PendingBanner({
  deadline,
  busy,
  keep,
  revert,
}: {
  deadline: string;
  busy: boolean;
  keep: () => void;
  revert: () => void;
}) {
  const t = useT();
  const now = useNow(true);
  const left = Math.max(
    0,
    Math.round((new Date(deadline).getTime() - now) / 1000),
  );
  const clock = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
  return (
    <div className="safe-banner fw-pending" role="status" aria-live="polite">
      <Undo2 className="size-4 shrink-0" aria-hidden />
      <p className="min-w-0 flex-1 text-sm">
        <span className="font-medium">
          {fill(t("fwPendingTitle"), { t: clock })}
        </span>{" "}
        <span className="text-muted-foreground">{t("fwPendingBody")}</span>
      </p>
      <div className="flex shrink-0 gap-2">
        <Button size="sm" variant="outline" disabled={busy} onClick={revert}>
          {t("fwRevertNow")}
        </Button>
        <Button size="sm" disabled={busy} onClick={keep}>
          <Check data-icon="inline-start" />
          {t("fwKeep")}
        </Button>
      </div>
    </div>
  );
}
