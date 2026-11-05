import { useContext, useEffect, useState } from "react";
import { ChevronDown, Loader2 } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import { trafficBytes } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import { flowTableBytes, groups as order, pendingChanges } from "./catalog";
import { SettingRow } from "./SettingRow";
import type { OptimizeChange, OptimizeGroup, OptimizePlan } from "./types";

function Rows({ changes }: { changes: OptimizeChange[] }) {
  return (
    <ul className="opt-settings">
      {changes.map((c) => (
        <SettingRow
          key={c.key}
          setting={c.key}
          current={c.current}
          value={c.value}
          note={c.note}
          reason={c.reason}
          managed={false}
          otherFile={c.other_file}
          otherValue={c.other_value}
        />
      ))}
    </ul>
  );
}

/** Reads the live plan for one or more groups and applies it after review. */
export function ApplyDialog({
  groups,
  onClose,
  apply,
}: {
  groups?: OptimizeGroup[];
  onClose: () => void;
  apply: (groups: OptimizeGroup[]) => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const key = groups?.join(",") ?? "";
  // The answer is kept with the selection it belongs to, so a new selection
  // shows a fresh skeleton without resetting state inside the effect.
  const [result, setResult] = useState<{
    key: string;
    plan?: OptimizePlan;
    error?: string;
  }>();
  const [busy, setBusy] = useState(false);
  const [showRest, setShowRest] = useState(false);
  useEffect(() => {
    if (!key) return;
    const controller = new AbortController();
    api<OptimizePlan>(
      `optimize/plan?groups=${key}`,
      undefined,
      controller.signal,
    )
      .then((plan) => setResult({ key, plan }))
      .catch((e) => {
        if (!controller.signal.aborted)
          setResult({ key, error: e instanceof Error ? e.message : String(e) });
      });
    return () => controller.abort();
  }, [key]);
  const current = result?.key === key ? result : undefined;
  const plan = current?.plan;
  const changes = plan ? pendingChanges(plan.changes) : [];
  const rest = plan ? plan.changes.filter((c) => c.note !== "change") : [];
  const kept = rest.filter((c) => c.note === "kept").length;
  const limit = plan?.changes.find(
    (c) => c.key === "net.netfilter.nf_conntrack_max",
  );
  const buckets = plan?.changes.find(
    (c) => c.key === "net.netfilter.nf_conntrack_buckets",
  );
  const title =
    groups?.length === 1
      ? t("optApplyTitle").replace("{group}", t(`optGroup_${groups[0]}`))
      : t("optRecommendedTitle");
  function close() {
    setShowRest(false);
    onClose();
  }
  return (
    <Dialog
      open={Boolean(groups)}
      onOpenChange={(open) => !open && !busy && close()}
    >
      <DialogContent
        closeLabel={t("close")}
        scrollLayout="body"
        className="sm:max-w-2xl"
      >
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{t("optApplyBody")}</DialogDescription>
        </DialogHeader>
        <DialogBody className="flex flex-col gap-5">
          {current?.error && (
            <Alert variant="destructive">
              <AlertDescription>{current.error}</AlertDescription>
            </Alert>
          )}
          {!current && (
            <div
              className="flex flex-col gap-2"
              aria-label={t("optLoadingPlan")}
            >
              {[0, 1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-14 w-full" />
              ))}
            </div>
          )}
          {plan && (
            <>
              <p className="opt-plan-summary">
                <strong>
                  {t("optPlanChanges").replace("{n}", String(changes.length))}
                </strong>
                {kept > 0 && (
                  <span>{t("optPlanKept").replace("{n}", String(kept))}</span>
                )}
              </p>
              {changes.length === 0 ? (
                <Alert>
                  <AlertDescription>{t("optNothing")}</AlertDescription>
                </Alert>
              ) : (
                order
                  .filter((g) => changes.some((c) => c.group === g))
                  .map((g) => (
                    <section key={g} className="flex flex-col gap-2">
                      {(groups?.length ?? 0) > 1 && (
                        <h3 className="opt-plan-group">{t(`optGroup_${g}`)}</h3>
                      )}
                      <Rows changes={changes.filter((c) => c.group === g)} />
                    </section>
                  ))
              )}
              {limit && buckets && limit.note === "change" && (
                <p className="text-xs leading-relaxed text-muted-foreground">
                  {t("optMemoryEstimate").replace(
                    "{v}",
                    trafficBytes(
                      flowTableBytes(
                        Number(limit.value),
                        Number(buckets.value),
                      ),
                      locale,
                    ),
                  )}
                </p>
              )}
              {rest.length > 0 && (
                <section className="flex flex-col gap-2">
                  <button
                    type="button"
                    className="opt-disclosure"
                    aria-expanded={showRest}
                    onClick={() => setShowRest(!showRest)}
                  >
                    {t("optUnchanged").replace("{n}", String(rest.length))}
                    <ChevronDown
                      className={showRest ? "size-4 rotate-180" : "size-4"}
                      aria-hidden
                    />
                  </button>
                  {showRest && <Rows changes={rest} />}
                </section>
              )}
            </>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={close}>
            {t("cancel")}
          </Button>
          <Button
            disabled={!groups || busy || changes.length === 0}
            onClick={() => {
              if (!groups) return;
              setBusy(true);
              apply(groups)
                .then(close)
                .catch(() => undefined)
                .finally(() => setBusy(false));
            }}
          >
            {busy && (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            )}
            {t("optApplyButton").replace("{n}", String(changes.length))}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
