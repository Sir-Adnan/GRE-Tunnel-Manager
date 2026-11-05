import { useContext, useState } from "react";
import { History as HistoryIcon, RotateCcw, ShieldCheck } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { PageTitle } from "@/components/shared";
import { LocaleContext, useT } from "@/lib/i18n";
import { number } from "@/lib/format";
import { useLoaded, useNow } from "@/features/operations/hooks";
import { stamp } from "@/features/health/format";
import { byDay, dayLabel } from "@/features/notifications/catalog";
import { ChangeLine } from "./ChangeLine";
import { RestoreDialog } from "./RestoreDialog";
import type { HistoryEntry, HistoryView } from "./types";

function Entry({
  entry,
  latest,
  restore,
}: {
  entry: HistoryEntry;
  latest: boolean;
  restore: (entry: HistoryEntry) => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [all, setAll] = useState(false);
  const shown = all ? entry.changes : entry.changes.slice(0, 4);
  return (
    <li className="hist-entry" data-latest={latest}>
      <span className="hist-dot" aria-hidden />
      <div className="hist-card">
        <header>
          <div className="flex min-w-0 flex-col gap-0.5">
            <span className="flex flex-wrap items-center gap-2">
              <time className="hist-time" dateTime={entry.time}>
                {stamp(entry.time, locale, undefined, false)}
              </time>
              {latest && <Badge variant="secondary">{t("histLatest")}</Badge>}
            </span>
            <span className="text-xs text-muted-foreground">
              {entry.invalid
                ? t("histInvalid")
                : t("histSummary")
                    .replace("{n}", number(entry.changes.length, locale))
                    .replace("{c}", number(entry.count, locale))}
            </span>
          </div>
          {!entry.invalid && (
            <Button variant="outline" size="sm" onClick={() => restore(entry)}>
              <RotateCcw data-icon="inline-start" />
              <span className="hidden sm:inline">{t("histRestore")}</span>
              <span className="sm:hidden">{t("histRestoreShort")}</span>
            </Button>
          )}
        </header>
        {shown.length > 0 && (
          <ul className="hist-changes">
            {shown.map((c) => (
              <ChangeLine key={c.id + c.kind} change={c} />
            ))}
          </ul>
        )}
        {entry.changes.length > 4 && (
          <Button
            variant="ghost"
            size="sm"
            className="self-start"
            onClick={() => setAll(!all)}
          >
            {all
              ? t("histShowLess")
              : t("histShowAll").replace("{n}", String(entry.changes.length))}
          </Button>
        )}
      </div>
    </li>
  );
}

/** Forwarding change history with one-click restore of an earlier state. */
export function History({ run }: { run: (request: unknown) => Promise<void> }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { value, error, reload } = useLoaded<HistoryView>("history", () => 60);
  const [restoring, setRestoring] = useState<HistoryEntry>();
  const now = useNow(false);
  const days = byDay(value?.entries ?? []).map((group) => ({
    day: group.day,
    label: dayLabel(group.events[0].time, now, locale, t),
    entries: group.events,
  }));
  return (
    <div className="page-stack">
      <PageTitle title={t("history")} description={t("histIntro")} />
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <section className="hist-hero">
        <span className="hist-hero-icon" aria-hidden>
          <HistoryIcon />
        </span>
        <div className="flex min-w-0 flex-col gap-1">
          <h2 className="text-base font-semibold">
            {value
              ? t("histHeroTitle").replace("{n}", number(value.total, locale))
              : t("history")}
          </h2>
          <p className="text-sm text-muted-foreground">{t("histHeroBody")}</p>
        </div>
        <p className="hist-hero-note">
          <ShieldCheck className="size-4 shrink-0" aria-hidden />
          {t("histSafety")}
        </p>
      </section>
      {!value && !error ? (
        <div className="flex flex-col gap-3">
          <Skeleton className="h-28 w-full" />
          <Skeleton className="h-28 w-full" />
        </div>
      ) : value && value.entries.length === 0 ? (
        <div className="hist-empty">
          <HistoryIcon aria-hidden />
          <p className="font-medium">{t("histEmptyTitle")}</p>
          <p className="text-sm text-muted-foreground">{t("histEmptyBody")}</p>
        </div>
      ) : (
        days.map((group, index) => (
          <section key={group.day} className="hist-day" aria-label={group.label}>
            <h2 className="hist-day-label">{group.label}</h2>
            <ol className="hist-timeline">
              {group.entries.map((entry, i) => (
                <Entry
                  key={entry.point}
                  entry={entry}
                  latest={index === 0 && i === 0}
                  restore={setRestoring}
                />
              ))}
            </ol>
          </section>
        ))
      )}
      <RestoreDialog
        key={restoring?.point ?? ""}
        entry={restoring}
        onClose={() => setRestoring(undefined)}
        restore={async (point, revision) => {
          await run({ action: "history-restore", history: { point, revision } });
          await reload();
        }}
      />
    </div>
  );
}
