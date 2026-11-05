import { useContext, useState } from "react";
import { CircleCheck, CircleX } from "lucide-react";
import { Segmented } from "@/components/Segmented";
import { engineName } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import type { Outage } from "@/features/operations/types";
import { duration, stamp } from "./format";

function reasonText(t: (key: string) => string, reason?: string) {
  if (!reason) return "";
  const text = t(`reason_${reason}`);
  return text === `reason_${reason}` ? reason : text;
}

/** Newest first; ongoing outages are visually and textually distinct. */
export function OutageList({
  outages,
  time,
  timezone,
}: {
  outages: Outage[];
  time: string;
  timezone: string;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [filter, setFilter] = useState("all");
  const ongoing = outages.filter((o) => !o.end).length;
  const shown = filter === "open" ? outages.filter((o) => !o.end) : outages;
  const now = new Date(time).getTime();
  return (
    <div className="flex flex-col gap-4">
      <Segmented
        label={t("healthOutagesTab")}
        value={filter}
        onChange={setFilter}
        options={[
          {
            value: "all",
            label: t("healthAllOutages"),
            count: String(outages.length),
          },
          {
            value: "open",
            label: t("healthOnlyOngoing"),
            count: String(ongoing),
          },
        ]}
      />
      {shown.length === 0 ? (
        <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
          {t("healthNoOutages")}
        </p>
      ) : (
        <ol className="outage-list">
          {shown.map((o) => {
            const end = o.end ? new Date(o.end).getTime() : now;
            const length = (end - new Date(o.start).getTime()) / 1000;
            return (
              <li key={o.id} data-open={!o.end}>
                <span className="outage-icon" aria-hidden>
                  {o.end ? <CircleCheck /> : <CircleX />}
                </span>
                <div className="flex min-w-0 flex-1 flex-col gap-1">
                  <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                    <strong className="text-sm font-medium">
                      <bdi>{o.name}</bdi>
                    </strong>
                    <span className="text-xs text-muted-foreground">
                      {engineName(o.engine)}
                    </span>
                    <code className="text-xs text-muted-foreground" dir="ltr">
                      {o.endpoint}
                    </code>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    <bdi>{stamp(o.start, locale, timezone)}</bdi>
                    {" · "}
                    {t(o.end ? "healthResolved" : "healthOngoing")}{" "}
                    {t("healthOutageFor").replace(
                      "{d}",
                      duration(length, locale),
                    )}
                    {o.reason && <> · {reasonText(t, o.reason)}</>}
                  </p>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}
