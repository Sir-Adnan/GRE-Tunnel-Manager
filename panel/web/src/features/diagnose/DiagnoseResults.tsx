// The guided check's result list, shared by the diagnosis dialog and the
// connection's Check tab: verdict, problems first, each with what to do.
import { useContext } from "react";
import { CircleAlert, CircleCheck, Info, TriangleAlert } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { LocaleContext, useT } from "@/lib/i18n";
import { milliseconds, stamp } from "@/features/health/format";
import { orderChecks, type DiagnoseReport } from "./order";

const icons = {
  ok: CircleCheck,
  info: Info,
  warn: TriangleAlert,
  fail: CircleAlert,
} as const;

export function DiagnoseResults({
  report,
  error,
}: {
  report?: DiagnoseReport;
  error: string;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  if (error)
    return (
      <Alert variant="destructive">
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  if (!report)
    return (
      <div className="flex flex-col gap-2" aria-busy>
        {[0, 1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-11 w-full" />
        ))}
        <p className="text-xs text-muted-foreground">{t("diagRunning")}</p>
      </div>
    );
  const problems = report.checks.filter(
    (c) => c.status === "fail" || c.status === "warn",
  ).length;
  const Verdict = icons[report.status];
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <div className="diag-verdict" data-status={report.status}>
        <Verdict aria-hidden />
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
                  <span className="text-sm font-medium">
                    {t(`diag_${c.key}`)}
                  </span>
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
  );
}
