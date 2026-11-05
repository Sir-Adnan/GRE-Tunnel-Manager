import { useContext, useState } from "react";
import { Segmented } from "@/components/Segmented";
import { engineName } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import type { MaintenanceEntry } from "@/features/operations/types";
import { stamp } from "@/features/health/format";
import { ResultBadge } from "./PlanCard";

const problems = new Set(["failed", "skipped", "cancelled"]);

/** Newest first. A list, not a table, so long messages wrap on phones. */
export function HistoryTable({
  history,
  timezone,
}: {
  history: MaintenanceEntry[];
  timezone: string;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [filter, setFilter] = useState("all");
  // Fixed broker sentences are translated; command output stays verbatim.
  const message = (text: string) => {
    const translated = t(`msg:${text}`);
    return translated === `msg:${text}` ? text : translated;
  };
  const shown =
    filter === "problems"
      ? history.filter((e) => problems.has(e.result))
      : history;
  return (
    <div className="flex flex-col gap-4">
      <Segmented
        label={t("mxHistoryTab")}
        value={filter}
        onChange={setFilter}
        options={[
          {
            value: "all",
            label: t("mxAllResults"),
            count: String(history.length),
          },
          {
            value: "problems",
            label: t("mxProblems"),
            count: String(history.filter((e) => problems.has(e.result)).length),
          },
        ]}
      />
      {shown.length === 0 ? (
        <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
          {t("mxHistoryEmpty")}
        </p>
      ) : (
        <ol className="history-list">
          {shown.map((entry) => (
            <li key={entry.id}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex min-w-0 flex-wrap items-center gap-2">
                  <ResultBadge result={entry.result} />
                  <strong className="text-sm font-medium">
                    <bdi>{entry.plan_name}</bdi>
                  </strong>
                  <span className="text-xs text-muted-foreground">
                    {t(`action_${entry.action}`)} ·{" "}
                    {t(`reason_${entry.reason}`)}
                  </span>
                </div>
                <time
                  className="text-xs text-muted-foreground tabular-nums"
                  dateTime={entry.started}
                >
                  <bdi>{stamp(entry.started, locale, timezone)}</bdi>
                </time>
              </div>
              {(entry.owner_name || entry.message) && (
                <p className="text-xs text-muted-foreground">
                  {entry.owner_name && (
                    <>
                      <bdi>{entry.owner_name}</bdi>
                      {entry.engine && <> ({engineName(entry.engine)})</>}
                      {entry.message && " · "}
                    </>
                  )}
                  {entry.message && (
                    <bdi className="break-words">{message(entry.message)}</bdi>
                  )}
                </p>
              )}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
