// What blocks traffic now, each with the way to fix it.
import { CircleAlert, CircleCheck, TriangleAlert, Wrench } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useT } from "@/lib/i18n";
import type { Finding } from "./model";
import { fill } from "./text";

export function Findings({
  items,
  busy,
  repair,
  openUFW,
}: {
  items: Finding[];
  busy: boolean;
  repair: () => void;
  openUFW: (id: string) => void;
}) {
  const t = useT();
  if (items.length === 0)
    return (
      <p className="fw-clear" role="status">
        <CircleCheck className="size-4 shrink-0" aria-hidden />
        {t("fwAllClear")}
      </p>
    );
  return (
    <section className="fw-findings" aria-labelledby="fw-attention">
      <h2 id="fw-attention" className="fw-section-title">
        {t("fwAttention")}
      </h2>
      <ul className="fw-finding-list">
        {items.map((f) => (
          <li key={f.id} className="fw-finding" data-level={f.level}>
            {f.level === "problem" ? (
              <CircleAlert className="fw-finding-icon" aria-hidden />
            ) : (
              <TriangleAlert className="fw-finding-icon" aria-hidden />
            )}
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium">{fill(t(f.key), f.vars)}</p>
              {f.key === "fwGuardMissing" && (
                <p className="text-xs text-muted-foreground">
                  {t("fwGuardFix")}
                </p>
              )}
              {f.key === "fwRelayClosed" && (
                <p className="text-xs text-muted-foreground">
                  {t("fwRelayClosedFix")}
                </p>
              )}
            </div>
            {f.fix === "repair" && (
              <Button size="sm" disabled={busy} onClick={repair}>
                <Wrench data-icon="inline-start" />
                {t("fwRepair")}
              </Button>
            )}
            {f.fix === "ufw" && f.connection && (
              <Button
                size="sm"
                variant="outline"
                disabled={busy}
                onClick={() => openUFW(f.connection!)}
              >
                {t("fwOpenInUFW")}
              </Button>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
