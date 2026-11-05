import { useContext, useState } from "react";
import { ChevronDown } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EngineGlyph } from "@/components/shared";
import { engineName } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import type { HealthOwner, HealthTarget } from "@/features/operations/types";
import { StatusPill, Sparkline, UptimeBars } from "./Indicators";
import { dayLabel, milliseconds, percent, stamp, uptimeTone } from "./format";

const kindKey = {
  tcp: "healthKindTcp",
  icmp: "healthKindIcmp",
  service: "healthKindService",
} as const;

function endpoint(target: HealthTarget) {
  if (target.kind === "service") return target.unit ?? "";
  if (!target.port) return target.address ?? "";
  return target.address?.includes(":")
    ? `[${target.address}]:${target.port}`
    : `${target.address}:${target.port}`;
}

function UptimeTriple({ owner }: { owner: HealthOwner }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  return (
    <dl className="uptime-triple">
      {(
        [
          ["healthWindow24h", owner.uptime_24h],
          ["healthWindow7d", owner.uptime_7d],
          ["healthWindow30d", owner.uptime_30d],
        ] as const
      ).map(([key, value]) => (
        <div key={key}>
          <dt>{t(key)}</dt>
          <dd data-tone={uptimeTone(value)}>
            <bdi dir="ltr">{percent(value, locale)}</bdi>
          </dd>
        </div>
      ))}
    </dl>
  );
}

function Targets({
  owner,
  time,
  timezone,
}: {
  owner: HealthOwner;
  time: string;
  timezone: string;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const today = new Date(time);
  return (
    <div className="health-detail">
      <div className="flex flex-col gap-2">
        <span className="text-xs text-muted-foreground">
          {t("healthLast30d").replace("{n}", String(owner.days.length))}
        </span>
        <UptimeBars
          className="is-days"
          cells={owner.days}
          label={t("healthLast30d").replace("{n}", String(owner.days.length))}
          cellLabel={(i) =>
            dayLabel(
              today.getTime() - (owner.days.length - 1 - i) * 86400000,
              locale,
              timezone,
            )
          }
        />
      </div>
      <ul className="health-targets">
        {owner.targets.map((target) => (
          <li key={target.key}>
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <StatusPill status={target.status} />
              <Badge variant="outline">{t(kindKey[target.kind])}</Badge>
              <code className="truncate text-xs" dir="ltr">
                {endpoint(target)}
              </code>
            </div>
            <div className="health-target-metrics">
              {target.kind !== "service" && (
                <Sparkline
                  points={target.recent}
                  label={`${t("healthRecentChecks")} · ${endpoint(target)}`}
                />
              )}
              <span className="tabular-nums">
                <bdi dir="ltr">
                  {target.kind === "service"
                    ? ""
                    : milliseconds(target.rtt_ms, locale)}
                </bdi>
              </span>
              <span
                className="tabular-nums"
                data-tone={uptimeTone(target.uptime_24h)}
              >
                <bdi dir="ltr">{percent(target.uptime_24h, locale)}</bdi>
              </span>
            </div>
            <p className="text-xs text-muted-foreground">
              {target.error
                ? t(`reason_${target.error}`).replace(/^reason_/, "")
                : t("healthSince").replace(
                    "{t}",
                    stamp(target.since, locale, timezone),
                  )}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Status board: one row per tunnel; destinations and 30-day history on expand. */
export function OwnerList({
  owners,
  time,
  timezone,
}: {
  owners: HealthOwner[];
  time: string;
  timezone: string;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [open, setOpen] = useState<string>();
  const hourStart = Math.floor(new Date(time).getTime() / 3600000) * 3600000;
  return (
    <ul className="health-list">
      {owners.map((owner) => {
        const expanded = open === owner.owner;
        const main = owner.targets.find((x) => x.kind !== "service");
        return (
          <li
            key={owner.owner}
            className="health-row"
            data-status={owner.status}
          >
            <div className="health-row-main">
              <div className="health-name">
                <span className="engine-icon">
                  <EngineGlyph engine={owner.engine} />
                </span>
                <div className="flex min-w-0 flex-col gap-1">
                  <strong className="truncate text-sm font-medium">
                    <bdi>{owner.name}</bdi>
                  </strong>
                  <span className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                    <StatusPill status={owner.status} />
                    <span>{engineName(owner.engine)}</span>
                  </span>
                </div>
              </div>
              <div className="health-latency">
                {main ? (
                  <Sparkline
                    points={main.recent}
                    label={`${t("healthRecentChecks")} · ${owner.name}`}
                  />
                ) : (
                  <span />
                )}
                <span className="tabular-nums text-sm font-medium">
                  <bdi dir="ltr">{milliseconds(owner.latency_ms, locale)}</bdi>
                </span>
              </div>
              <UptimeBars
                className="health-hours"
                cells={owner.hours}
                label={`${t("healthLast24h")} · ${owner.name}`}
                cellLabel={(i) =>
                  stamp(hourStart - (23 - i) * 3600000, locale, timezone, false)
                }
              />
              <UptimeTriple owner={owner} />
              <Button
                variant="ghost"
                size="sm"
                className="health-expand"
                aria-expanded={expanded}
                aria-label={t(
                  expanded ? "healthHideChecks" : "healthShowChecks",
                )}
                onClick={() => setOpen(expanded ? undefined : owner.owner)}
              >
                <span className="text-xs">
                  {t("healthDestinations")} ·{" "}
                  <bdi dir="ltr">{owner.targets.length}</bdi>
                </span>
                <ChevronDown
                  data-icon="inline-end"
                  className={expanded ? "rotate-180" : ""}
                />
              </Button>
            </div>
            {expanded && (
              <Targets owner={owner} time={time} timezone={timezone} />
            )}
          </li>
        );
      })}
    </ul>
  );
}
