import { useCallback, useContext, useEffect, useState } from "react";
import {
  CircleAlert,
  CircleCheck,
  Info,
  Loader2,
  RefreshCw,
  Stethoscope,
  TriangleAlert,
} from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import { LocaleContext, useT } from "@/lib/i18n";
import { milliseconds, stamp } from "@/features/health/format";
import { orderChecks, type DiagnoseReport } from "./order";

const icons = {
  ok: CircleCheck,
  info: Info,
  warn: TriangleAlert,
  fail: CircleAlert,
} as const;

/** The guided "why is this down" check for one connection or GRE tunnel. */
export function DiagnoseDialog({
  owner,
  name,
  onClose,
}: {
  owner?: string;
  name?: string;
  onClose: () => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [report, setReport] = useState<DiagnoseReport>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    if (!owner) return;
    setBusy(true);
    setError("");
    try {
      setReport(
        await api<DiagnoseReport>(`diagnose?owner=${encodeURIComponent(owner)}`),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [owner]);
  // Callers remount the dialog per owner (key), so state starts empty and
  // the first check runs as soon as it opens.
  useEffect(() => {
    if (!owner) return;
    const controller = new AbortController();
    api<DiagnoseReport>(
      `diagnose?owner=${encodeURIComponent(owner)}`,
      undefined,
      controller.signal,
    )
      .then(setReport)
      .catch((e) => {
        if (!controller.signal.aborted)
          setError(e instanceof Error ? e.message : String(e));
      });
    return () => controller.abort();
  }, [owner]);
  const problems = report?.checks.filter(
    (c) => c.status === "fail" || c.status === "warn",
  ).length;
  return (
    <Dialog open={Boolean(owner)} onOpenChange={(open) => !open && onClose()}>
      <DialogContent closeLabel={t("close")} className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Stethoscope className="size-4 text-muted-foreground" aria-hidden />
            {t("diagTitle")}
          </DialogTitle>
          <DialogDescription>
            <bdi>{name || owner}</bdi> · {t("diagIntro")}
          </DialogDescription>
        </DialogHeader>
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {!report && !error ? (
          <div className="flex flex-col gap-2" aria-busy>
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-11 w-full" />
            ))}
            <p className="text-xs text-muted-foreground">{t("diagRunning")}</p>
          </div>
        ) : report ? (
          <div className="flex min-w-0 flex-col gap-3">
            <div className="diag-verdict" data-status={report.status}>
              {(() => {
                const Icon = icons[report.status];
                return <Icon aria-hidden />;
              })()}
              <div className="flex min-w-0 flex-col gap-0.5">
                <strong>
                  {problems
                    ? t("diagProblems").replace("{n}", String(problems))
                    : t("diagAllGood")}
                </strong>
                <span className="text-xs text-muted-foreground">
                  {t("diagAt").replace("{t}", stamp(report.time, locale))}
                </span>
              </div>
            </div>
            {report.outage && (
              <p className="text-xs text-muted-foreground">
                {t(report.outage.end ? "diagLastOutage" : "diagOpenOutage").replace(
                  "{t}",
                  stamp(report.outage.start, locale),
                )}
              </p>
            )}
            <ol className="diag-list">
              {orderChecks(report.checks).map((c, i) => {
                const Icon = icons[c.status];
                return (
                  <li key={c.key + i} className="diag-check" data-status={c.status}>
                    <Icon className="diag-icon" aria-hidden />
                    <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                      <span className="flex flex-wrap items-baseline justify-between gap-x-3">
                        <span className="text-sm font-medium">{t(`diag_${c.key}`)}</span>
                        {c.rtt_ms != null && (
                          <span className="text-xs tabular-nums text-muted-foreground">
                            <bdi dir="ltr">{milliseconds(c.rtt_ms, locale)}</bdi>
                          </span>
                        )}
                      </span>
                      {c.detail && (
                        <code dir="ltr" className="diag-detail">
                          {c.detail}
                        </code>
                      )}
                      {(c.status === "fail" || c.status === "warn") && (
                        <p className="diag-fix">{t(`diagFix_${c.key}`)}</p>
                      )}
                    </div>
                    <span className="sr-only">{t(`diagStatus_${c.status}`)}</span>
                  </li>
                );
              })}
            </ol>
            <p className="text-xs text-muted-foreground">{t("diagScope")}</p>
          </div>
        ) : null}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t("close")}
          </Button>
          <Button disabled={busy} onClick={() => void load()}>
            {busy ? (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            ) : (
              <RefreshCw data-icon="inline-start" />
            )}
            {t("diagAgain")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
