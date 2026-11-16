// Live packet path: clients → firewall → this server → each destination,
// with rates between samples and a verdict that names where traffic stops.
import { useContext, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  CircleAlert,
  CircleCheck,
  CircleDashed,
  Loader2,
  Server,
  ShieldCheck,
  Target,
  TriangleAlert,
  Users,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { HelpTip } from "@/components/help";
import { LocaleContext, useT } from "@/lib/i18n";
import { bitRate, engineName, number, trafficBytes } from "@/lib/format";
import { usePanelRoute } from "@/lib/use-panel-route";
import type { Connection } from "@/lib/api";
import {
  activity,
  pathView,
  silentDestinations,
  type Flow,
  type PathView,
  type Verdict,
} from "./model";
import { pathSeconds, usePath } from "./usePath";
import { firewallChanged } from "./badges";

type Tone = "ok" | "warn" | "problem" | "idle";

const verdictTone: Record<Verdict, Tone> = {
  disabled: "idle",
  idle: "idle",
  dropped: "problem",
  stuck: "problem",
  noAnswer: "problem",
  partial: "warn",
  flowing: "ok",
};

const toneIcon: Record<Tone, LucideIcon> = {
  ok: CircleCheck,
  warn: TriangleAlert,
  problem: CircleAlert,
  idle: CircleDashed,
};

function fill(text: string, vars: Record<string, string>) {
  return text.replace(/\{(\w+)\}/g, (m, k: string) => vars[k] ?? m);
}

export function PacketPath({
  connection,
  hostname,
  run,
}: {
  connection: Connection;
  hostname: string;
  run?: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { navigate } = usePanelRoute();
  const { next, prev, error } = usePath(connection.id);
  const [fixing, setFixing] = useState(false);
  const n = (value: number, digits = 0) => number(value, locale, digits);

  if (!next)
    return error ? (
      <Alert variant="destructive">
        <AlertDescription>
          {t("pathLoadFailed")} <bdi dir="ltr">{error}</bdi>
        </AlertDescription>
      </Alert>
    ) : (
      <div className="flex flex-col gap-2" aria-busy>
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-28 w-full" />
      </div>
    );

  const view = pathView(next, prev);
  const tone = verdictTone[view.verdict];
  const VerdictIcon = toneIcon[tone];
  const tool = view.drops.join(", ");
  const body =
    view.verdict === "noAnswer" && !view.kernel
      ? t("pathVerdictBody_noAnswerRelay")
      : fill(t(`pathVerdictBody_${view.verdict}`), {
          tool,
          list: silentDestinations(view).join(", "),
        });

  const rate = (f: Flow | undefined, live: string, total: string) =>
    f?.rate !== undefined
      ? fill(t(live), { n: n(f.rate, f.rate < 10 ? 1 : 0) })
      : fill(t(total), { n: n(f?.total ?? 0) });

  async function repair() {
    if (!run) return;
    setFixing(true);
    try {
      await run({ action: "firewall-repair" });
      // Connection cards reread their firewall badges.
      window.dispatchEvent(new Event(firewallChanged));
    } catch {
      /* the operation dialog shows the error */
    } finally {
      setFixing(false);
    }
  }

  return (
    <section className="path" aria-labelledby={`path-${connection.id}`}>
      <div className="path-head">
        <h3 id={`path-${connection.id}`} className="path-title">
          {t("pathTitle")}
        </h3>
        <HelpTip label={`${t("pathTitle")} · ?`}>{t("pathHelp")}</HelpTip>
        <span
          className="path-pulse"
          data-live={view.live || undefined}
          aria-hidden
        />
      </div>
      <div
        className="path-verdict"
        data-tone={tone}
        role="status"
        aria-live="polite"
      >
        <VerdictIcon className="path-verdict-icon" aria-hidden />
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <strong className="text-sm">
            {t(`pathVerdict_${view.verdict}`)}
          </strong>
          <p className="text-xs leading-relaxed text-muted-foreground">
            <bdi>{body}</bdi>
          </p>
          {view.verdict === "dropped" && (
            <div className="mt-1 flex flex-wrap gap-2">
              {run && (
                <Button
                  size="sm"
                  disabled={fixing}
                  onClick={() => void repair()}
                >
                  {fixing ? (
                    <Loader2
                      data-icon="inline-start"
                      className="animate-spin"
                    />
                  ) : (
                    <Wrench data-icon="inline-start" />
                  )}
                  {t("pathFixNow")}
                </Button>
              )}
              <Button
                size="sm"
                variant="outline"
                onClick={() => navigate("firewall")}
              >
                <ShieldCheck data-icon="inline-start" />
                {t("pathOpenFirewall")}
              </Button>
            </div>
          )}
        </div>
      </div>
      {next.enabled && (
        <ol className="path-flow">
          <Node
            icon={Users}
            label={t("pathClients")}
            state={activity(view.incoming) > 0 ? "ok" : "idle"}
          >
            <span className="path-value">
              {view.kernel
                ? rate(view.incoming, "pathNewRate", "pathNewTotal")
                : fill(t("pathConnected"), { n: n(view.clients ?? 0) })}
            </span>
          </Node>
          {(view.blocked || view.drops.length > 0) && (
            <Node
              icon={ShieldCheck}
              label={t("pathFirewall")}
              state={
                view.drops.length
                  ? "problem"
                  : activity(view.blocked) > 0
                    ? "warn"
                    : "ok"
              }
              stops={view.verdict === "dropped"}
            >
              {view.drops.length > 0 && (
                <span className="path-value">
                  {fill(t("pathDropsHere"), { tool })}
                </span>
              )}
              {view.blocked && (
                <span className={view.drops.length ? "path-sub" : "path-value"}>
                  {activity(view.blocked) > 0
                    ? rate(view.blocked, "pathBlockedRate", "pathBlockedTotal")
                    : t("pathNoBlocks")}
                </span>
              )}
            </Node>
          )}
          <Node
            icon={Server}
            label={hostname}
            state={
              view.verdict === "stuck"
                ? "problem"
                : activity(view.incoming) > 0
                  ? "ok"
                  : "idle"
            }
            stops={view.verdict === "stuck"}
          >
            <span className="path-value">
              {view.kernel
                ? t("pathForward")
                : fill(t("pathRelay"), {
                    engine: engineName(connection.engine),
                  })}
            </span>
            {view.kernel && (
              <span className="path-sub">
                {t(
                  connection.snat === "masquerade"
                    ? "pathSourceServer"
                    : "pathSourceClient",
                )}
              </span>
            )}
          </Node>
          <li className="path-targets">
            <ul className="flex flex-col gap-2">
              {view.destinations.map((d) => (
                <Destination
                  key={d.address}
                  view={view}
                  address={d.address}
                  fallback=""
                />
              ))}
              {view.destinations.length === 0 && (
                <Destination
                  view={view}
                  address=""
                  fallback={connection.targets[0]?.ip ?? ""}
                />
              )}
            </ul>
          </li>
        </ol>
      )}
      <p className="path-foot">
        {view.live
          ? fill(t("pathLive"), { n: String(pathSeconds) })
          : view.kernel
            ? t("pathTotals")
            : fill(t("pathLive"), { n: String(pathSeconds) })}
      </p>
    </section>
  );
}

function Destination({
  view,
  address,
  fallback,
}: {
  view: PathView;
  address: string;
  fallback: string;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const n = (value: number, digits = 0) => number(value, locale, digits);
  const d = view.destinations.find((x) => x.address === address);
  const sent = activity(d?.out),
    answered = activity(d?.back);
  // Traffic that stopped earlier (dropped, stuck) is not this destination's fault.
  const earlier = view.verdict === "dropped" || view.verdict === "stuck";
  const state: Tone = view.kernel
    ? sent > 0 && !answered && !earlier
      ? "problem"
      : answered > 0
        ? "ok"
        : "idle"
    : (d?.upstream ?? 0) > 0
      ? "ok"
      : view.clients
        ? "problem"
        : "idle";
  const Icon = toneIcon[state];
  // Units stay left-to-right; the packet rate reads in the page's language.
  const traffic = (f: Flow | undefined) =>
    f?.byteRate !== undefined ? (
      <>
        <bdi dir="ltr">{bitRate(f.byteRate, locale)}</bdi>
        <span aria-hidden>·</span>
        <span>
          {fill(t("pathPackets"), {
            n: n(f.rate ?? 0, (f.rate ?? 0) < 10 ? 1 : 0),
          })}
        </span>
      </>
    ) : (
      <bdi dir="ltr">{trafficBytes(f?.bytes ?? 0, locale)}</bdi>
    );
  return (
    <li className="path-target" data-state={state}>
      <Target className="path-node-icon" aria-hidden />
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <span className="flex min-w-0 items-center justify-between gap-2">
          <span className="text-xs text-muted-foreground">
            {t("pathDestination")}
          </span>
          <Icon className="size-3.5 shrink-0" data-tone={state} aria-hidden />
        </span>
        <bdi
          dir="ltr"
          className="max-w-full self-start truncate font-mono text-sm"
        >
          {address || fallback || "—"}
        </bdi>
        {view.kernel ? (
          <span className="path-traffic">
            <span>
              <ArrowUp aria-hidden />
              <span className="sr-only">{t("pathSent")}</span>
              {traffic(d?.out)}
            </span>
            <span data-missing={state === "problem" || undefined}>
              <ArrowDown aria-hidden />
              <span className="sr-only">{t("pathReceived")}</span>
              {traffic(d?.back)}
            </span>
          </span>
        ) : (
          <span className="path-sub">
            {fill(t("pathOpen"), { n: n(d?.upstream ?? 0) })}
          </span>
        )}
        {state === "problem" && (
          <span className="path-stop">{t("pathStopsHere")}</span>
        )}
      </div>
    </li>
  );
}

function Node({
  icon: Icon,
  label,
  state,
  stops,
  children,
}: {
  icon: LucideIcon;
  label: string;
  state: Tone;
  stops?: boolean;
  children: React.ReactNode;
}) {
  const t = useT();
  return (
    <li className="path-node" data-state={state}>
      <Icon className="path-node-icon" aria-hidden />
      <div className="flex min-w-0 flex-1 flex-col gap-0.5">
        <span className="truncate text-xs text-muted-foreground">
          <bdi>{label}</bdi>
        </span>
        {children}
        {stops && <span className="path-stop">{t("pathStopsHere")}</span>}
      </div>
    </li>
  );
}
