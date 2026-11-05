import { useContext } from "react";
import { Activity, Gauge, Loader2, Ruler, Shuffle } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { HelpTip } from "@/components/help";
import { number } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import { useOnDemand } from "@/features/operations/hooks";
import type {
  FailoverStatus,
  FlowCounts,
  MTUResult,
} from "@/features/operations/types";
import { milliseconds, stamp } from "./format";

/** Which destinations failover keeps out of new connections, and why. */
export function FailoverNotice({
  status,
  endpoints,
  timezone,
}: {
  status?: FailoverStatus;
  endpoints: string[];
  timezone: string;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  if (!status || (!status.excluded.length && !status.error)) return null;
  const list = status.excluded
    .map((i) => endpoints[i - 1] ?? `#${i}`)
    .join(locale === "fa" ? "، " : ", ");
  const [before, after = ""] = t("healthFailoverExcluded").split("{list}");
  return (
    <Alert className="failover-notice" data-error={Boolean(status.error)}>
      <Shuffle />
      <AlertDescription className="flex flex-col gap-1">
        <span className="font-medium">{t("healthFailover")}</span>
        {status.excluded.length > 0 && (
          <span>
            {before}
            <bdi dir="ltr" className="font-mono text-xs">
              {list}
            </bdi>
            {after}
          </span>
        )}
        {status.changed && (
          <span className="text-xs text-muted-foreground">
            {t("healthSince").replace(
              "{t}",
              stamp(status.changed, locale, timezone),
            )}
          </span>
        )}
        {status.error && (
          <span className="text-xs text-destructive">
            {t("healthFailoverError").replace("{e}", status.error)}
          </span>
        )}
      </AlertDescription>
    </Alert>
  );
}

/** New connections per destination of one nftables forward, on request. */
export function FlowDistribution({
  owner,
  endpoints,
}: {
  owner: string;
  endpoints: string[];
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { value, error, busy, load } = useOnDemand<FlowCounts>(
    `health/flows?owner=${encodeURIComponent(owner)}`,
  );
  const peak = Math.max(1, ...(value?.destinations ?? [0]));
  return (
    <section className="tunnel-tool">
      <header>
        <span className="flex items-center gap-2 text-sm font-medium">
          <Gauge className="size-4 text-muted-foreground" />
          {t("healthFlows")}
          <HelpTip>{t("healthFlowsHelp")}</HelpTip>
        </span>
        <Button variant="outline" size="sm" disabled={busy} onClick={load}>
          {busy && (
            <Loader2 data-icon="inline-start" className="animate-spin" />
          )}
          {value ? t("refresh") : t("healthFlowsLoad")}
        </Button>
      </header>
      {error && <p className="text-xs text-destructive">{error}</p>}
      {value && (
        <>
          <ul className="flow-bars">
            {value.destinations.map((n, i) => (
              <li key={i}>
                <code dir="ltr" className="truncate text-xs">
                  {endpoints[i] ?? `#${i + 1}`}
                </code>
                <span className="flow-bar" aria-hidden>
                  <span style={{ inlineSize: `${(100 * n) / peak}%` }} />
                </span>
                <span className="text-xs tabular-nums">
                  <bdi dir="ltr">{number(n, locale)}</bdi>
                </span>
              </li>
            ))}
          </ul>
          <span className="text-xs text-muted-foreground">
            {t("healthFlowsTotal").replace("{n}", number(value.total, locale))}
          </span>
        </>
      )}
    </section>
  );
}

/** On-demand path MTU test through one GRE link. */
export function MTUTest({ owner }: { owner: string }) {
  const t = useT();
  const { value, error, busy, load } = useOnDemand<MTUResult>(
    `health/mtu?owner=${encodeURIComponent(owner)}`,
  );
  return (
    <section className="tunnel-tool">
      <header>
        <span className="flex items-center gap-2 text-sm font-medium">
          <Ruler className="size-4 text-muted-foreground" />
          {t("healthMtu")}
          <HelpTip>{t("healthMtuHelp")}</HelpTip>
        </span>
        <Button variant="outline" size="sm" disabled={busy} onClick={load}>
          {busy && (
            <Loader2 data-icon="inline-start" className="animate-spin" />
          )}
          {t("healthMtuTest")}
        </Button>
      </header>
      {error && <p className="text-xs text-destructive">{error}</p>}
      {value && (
        <div className="flex flex-col gap-1 text-sm">
          {value.path_mtu === 0 ? (
            <span className="text-destructive">{t("healthMtuNone")}</span>
          ) : (
            <>
              <span>
                {t("healthMtuResult")
                  .replace("{path}", String(value.path_mtu))
                  .replace("{mtu}", String(value.interface_mtu))}
              </span>
              <span
                className={
                  value.path_mtu < value.interface_mtu
                    ? "opt-warn text-xs"
                    : "text-xs text-muted-foreground"
                }
              >
                {value.path_mtu < value.interface_mtu
                  ? t("healthMtuLower").replaceAll(
                      "{path}",
                      String(value.path_mtu),
                    )
                  : t("healthMtuOk")}
              </span>
            </>
          )}
        </div>
      )}
    </section>
  );
}

type QualityReport = {
  peer: string;
  sent: number;
  received: number;
  loss_percent: number;
  min_ms?: number;
  avg_ms?: number;
  max_ms?: number;
  jitter_ms?: number;
  samples: number[];
};

/** Twenty pings through one GRE link: latency, jitter and loss. */
export function QualityTest({ owner }: { owner: string }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { value, error, busy, load } = useOnDemand<QualityReport>(
    `health/quality?owner=${encodeURIComponent(owner)}`,
  );
  const peak = Math.max(1, ...(value?.samples ?? [1]));
  return (
    <section className="tunnel-tool">
      <header>
        <span className="flex items-center gap-2 text-sm font-medium">
          <Activity className="size-4 text-muted-foreground" />
          {t("healthQuality")}
          <HelpTip>{t("healthQualityHelp")}</HelpTip>
        </span>
        <Button variant="outline" size="sm" disabled={busy} onClick={load}>
          {busy && (
            <Loader2 data-icon="inline-start" className="animate-spin" />
          )}
          {busy ? t("healthQualityRunning") : t("healthQualityRun")}
        </Button>
      </header>
      {error && <p className="text-xs text-destructive">{error}</p>}
      {value && (
        <>
          <dl className="quality-stats">
            {(
              [
                ["healthQualityAvg", milliseconds(value.avg_ms, locale)],
                ["healthQualityJitter", milliseconds(value.jitter_ms, locale)],
                ["healthQualityLoss", `${number(value.loss_percent, locale)}%`],
                [
                  "healthQualityRange",
                  value.min_ms == null
                    ? "—"
                    : `${milliseconds(value.min_ms, locale)} – ${milliseconds(value.max_ms, locale)}`,
                ],
              ] as const
            ).map(([label, text]) => (
              <div key={label}>
                <dt>{t(label)}</dt>
                <dd
                  data-tone={
                    label === "healthQualityLoss" && value.loss_percent > 0
                      ? value.loss_percent >= 5
                        ? "bad"
                        : "warn"
                      : undefined
                  }
                >
                  <bdi dir="ltr">{text}</bdi>
                </dd>
              </div>
            ))}
          </dl>
          <ol className="quality-bars" aria-label={t("healthQualitySamples")}>
            {value.samples.map((s, i) => (
              <li
                key={i}
                data-lost={s < 0}
                style={{ blockSize: s < 0 ? "100%" : `${Math.max(8, (100 * s) / peak)}%` }}
                title={s < 0 ? t("healthQualityLost") : `${s} ms`}
              />
            ))}
          </ol>
        </>
      )}
    </section>
  );
}
