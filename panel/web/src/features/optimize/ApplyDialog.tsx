import { useContext, useEffect, useMemo, useState } from "react";
import {
  ChevronDown,
  Loader2,
  PenLine,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
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
import {
  customValid,
  flowTableBytes,
  groups as order,
  pendingChanges,
} from "./catalog";
import { CustomField } from "./CustomField";
import { SettingRow } from "./SettingRow";
import type {
  OptimizeChange,
  OptimizeGroup,
  OptimizePlan,
  OptimizeProfile,
} from "./types";

export type ApplyRequest = {
  groups: OptimizeGroup[];
  set: Record<string, string>;
  allowWorse: boolean;
  /** Minutes of auto-undo watch; 0 is off. */
  watch: number;
};

function planPath(
  groups: OptimizeGroup[],
  profile: OptimizeProfile,
  set: Record<string, string>,
): string {
  const query = new URLSearchParams({
    groups: groups.join(","),
    level: profile.level,
    goal: profile.goal,
  });
  for (const [key, value] of Object.entries(set).sort())
    query.append("set", `${key}=${value}`);
  return `optimize/plan?${query.toString()}`;
}

/** Waits until the value has been still for a moment (typing custom values). */
function useSettled<T>(value: T, ms: number): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setSettled(value), ms);
    return () => window.clearTimeout(timer);
  }, [value, ms]);
  return settled;
}

/**
 * Reads the live plan of a profile for one or more groups, lets each value
 * be customized within its bounds, and applies it after review. Custom
 * values worse than the server's original need an explicit confirmation.
 */
export function ApplyDialog({
  groups,
  profile,
  watchMinutes,
  onClose,
  apply,
}: {
  groups?: OptimizeGroup[];
  profile: OptimizeProfile;
  /** Offered auto-undo windows; empty while Health monitoring is off. */
  watchMinutes: number[];
  onClose: () => void;
  apply: (request: ApplyRequest) => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  // The value each editor opened with: unchanged drafts are not custom.
  const [starts, setStarts] = useState<Record<string, string>>({});
  const [accept, setAccept] = useState(false);
  const [watch, setWatch] = useState(10);
  const [busy, setBusy] = useState(false);
  const [showRest, setShowRest] = useState(false);
  // The answer is kept with the selection it belongs to (base) and the exact
  // request (path): a new selection shows a skeleton, while a custom value
  // is checked the last answer stays visible.
  const [result, setResult] = useState<{
    base: string;
    path: string;
    plan?: OptimizePlan;
    error?: string;
  }>();
  const base = groups ? planPath(groups, profile, {}) : "";
  const current = result?.base === base ? result : undefined;
  const bounds = current?.plan?.changes;
  // Only drafts inside the server's bounds are sent; others stay local.
  const valid = useMemo(() => {
    const out: Record<string, string> = {};
    for (const [key, value] of Object.entries(drafts)) {
      const change = bounds?.find((c) => c.key === key);
      if (value !== starts[key] && change && customValid(change, value))
        out[key] = value;
    }
    return out;
  }, [drafts, starts, bounds]);
  const settled = useSettled(valid, 350);
  const path = groups ? planPath(groups, profile, settled) : "";
  useEffect(() => {
    if (!path) return;
    const controller = new AbortController();
    api<OptimizePlan>(path, undefined, controller.signal)
      .then((plan) => setResult({ base, path, plan }))
      .catch((e) => {
        if (!controller.signal.aborted)
          setResult({
            base,
            path,
            error: e instanceof Error ? e.message : String(e),
          });
      });
    return () => controller.abort();
  }, [base, path]);
  const checking = Boolean(
    current && (current.path !== path || settled !== valid),
  );
  const plan = current?.plan;
  const changes = plan ? pendingChanges(plan.changes) : [];
  const rest = plan ? plan.changes.filter((c) => !changes.includes(c)) : [];
  const kept = rest.filter((c) => c.note === "kept").length;
  const worse = changes.filter((c) => c.note === "worse");
  const invalid = plan
    ? plan.changes.some(
        (c) => c.key in drafts && !customValid(c, drafts[c.key]),
      )
    : false;
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
    setDrafts({});
    setStarts({});
    setAccept(false);
    onClose();
  }
  function rows(list: OptimizeChange[]) {
    return (
      <ul className="opt-settings">
        {list.map((c) => {
          const editing = c.key in drafts;
          return (
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
              action={
                c.kind && c.note !== "missing" && !editing ? (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="opt-edit"
                    onClick={() => {
                      setDrafts({ ...drafts, [c.key]: c.value });
                      setStarts({ ...starts, [c.key]: c.value });
                    }}
                  >
                    <PenLine data-icon="inline-start" />
                    {t("optEdit")}
                  </Button>
                ) : undefined
              }
            >
              {editing && (
                <CustomField
                  change={c}
                  draft={drafts[c.key]}
                  onChange={(value) => setDrafts({ ...drafts, [c.key]: value })}
                  onReset={() => {
                    const next = { ...drafts };
                    delete next[c.key];
                    setDrafts(next);
                  }}
                />
              )}
            </SettingRow>
          );
        })}
      </ul>
    );
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
          <DialogDescription>
            {t("optApplyProfile")
              .replace("{level}", t(`optLevel_${profile.level}`))
              .replace("{goal}", t(`optGoal_${profile.goal}`))}{" "}
            {t("optApplyBody")}
          </DialogDescription>
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
              <p className="opt-plan-summary" aria-live="polite">
                <strong>
                  {t("optPlanChanges").replace("{n}", String(changes.length))}
                </strong>
                {kept > 0 && (
                  <span>{t("optPlanKept").replace("{n}", String(kept))}</span>
                )}
                <span>{t("optPlanEditHint")}</span>
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
                      {rows(changes.filter((c) => c.group === g))}
                    </section>
                  ))
              )}
              {limit && buckets && pendingChanges([limit]).length > 0 && (
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
                  {showRest && rows(rest)}
                </section>
              )}
              {worse.length > 0 && (
                <Alert variant="destructive">
                  <TriangleAlert />
                  <AlertTitle>
                    {t("optWorseTitle").replace("{n}", String(worse.length))}
                  </AlertTitle>
                  <AlertDescription className="flex flex-col gap-3">
                    <p>{t("optWorseBody")}</p>
                    <label className="flex items-start gap-2 text-foreground">
                      <Checkbox
                        checked={accept}
                        onCheckedChange={(v) => setAccept(v === true)}
                        className="mt-0.5"
                      />
                      <span>{t("optWorseAccept")}</span>
                    </label>
                  </AlertDescription>
                </Alert>
              )}
              <div className="opt-watch-field">
                <ShieldCheck className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                <label htmlFor="opt-watch" className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <span className="text-sm font-medium">{t("optWatch")}</span>
                  <span className="text-xs text-muted-foreground">
                    {watchMinutes.length ? t("optWatchHelp") : t("optWatchNeedsHealth")}
                  </span>
                </label>
                <NativeSelect
                  id="opt-watch"
                  size="sm"
                  value={watchMinutes.length ? String(watch) : "0"}
                  disabled={!watchMinutes.length || busy}
                  onChange={(e) => setWatch(Number(e.target.value))}
                >
                  <NativeSelectOption value="0">{t("optWatchOff")}</NativeSelectOption>
                  {watchMinutes.map((m) => (
                    <NativeSelectOption key={m} value={String(m)}>
                      {t("optWatchMinutes").replace("{n}", String(m))}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              </div>
            </>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={close}>
            {t("cancel")}
          </Button>
          <Button
            disabled={
              !groups ||
              busy ||
              checking ||
              invalid ||
              changes.length === 0 ||
              (worse.length > 0 && !accept)
            }
            onClick={() => {
              if (!groups) return;
              setBusy(true);
              apply({
                groups,
                set: valid,
                allowWorse: worse.length > 0 && accept,
                watch: watchMinutes.includes(watch) ? watch : 0,
              })
                .then(close)
                .catch(() => undefined)
                .finally(() => setBusy(false));
            }}
          >
            {(busy || checking) && (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            )}
            {t("optApplyButton").replace("{n}", String(changes.length))}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
