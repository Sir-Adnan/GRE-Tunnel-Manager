// A live picture of the connection being built: incoming ports, this server,
// each destination (with what a domain resolves to) and the protection on it.
import { useContext } from "react";
import { ArrowDown, Globe, HeartPulse, Server, ShieldCheck, Undo2, Users } from "lucide-react";
import { LocaleContext, useT } from "@/lib/i18n";
import { number } from "@/lib/format";
import { engineName } from "@/lib/format";
import { EngineGlyph } from "@/components/shared";
import type { Connection } from "@/lib/api";
import { isHostname, parseSpans, remoteSpans, spanText, totalPorts } from "@/lib/ports";
import type { Protection } from "./protection";

export function RouteMap({
  value,
  hostname,
  resolved,
  protection,
  healthOn,
  safeMinutes,
}: {
  value: Connection;
  hostname: string;
  resolved: Record<string, string[] | undefined>;
  protection: Protection;
  healthOn: boolean;
  safeMinutes: number;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const kernel = value.engine === "nftables" || value.engine === "iptables";
  const { spans, error } = parseSpans(value.ports, kernel);
  const remote = remoteSpans(spans, value.port_mode || "", value.remote_ports || "", value.targets[0]?.port || 0);
  const ports = totalPorts(spans);
  const rules = kernel ? spans.length : ports;
  const monitored = healthOn && protection.monitor;
  return (
    <aside className="route-map" aria-label={t("routeMap")}>
      <p className="route-map-title">{t("routeMap")}</p>
      <div className="route-node">
        <Users aria-hidden />
        <div className="min-w-0">
          <p className="text-xs text-muted-foreground">{t("routeClients")}</p>
          <p className="truncate font-mono text-sm" dir="ltr">
            {value.ports && !error ? `:${value.ports}` : "—"} <span className="text-muted-foreground">{value.protocol.toUpperCase()}</span>
          </p>
          {!error && ports > 0 && (
            <p className="text-xs text-muted-foreground">
              {t("routePorts").replace("{n}", number(ports, locale)).replace("{r}", number(rules, locale))}
            </p>
          )}
        </div>
      </div>
      <ArrowDown className="route-arrow" aria-hidden />
      <div className="route-node is-server">
        <Server aria-hidden />
        <div className="min-w-0">
          <p className="truncate text-sm font-medium">{hostname}</p>
          <p className="flex items-center gap-1 text-xs text-muted-foreground">
            <EngineGlyph engine={value.engine} />
            <bdi>{engineName(value.engine)}</bdi>
            {value.targets.length > 1 && <> · {t(value.strategy)}</>}
          </p>
        </div>
      </div>
      <ArrowDown className="route-arrow" aria-hidden />
      <ol className="route-targets">
        {value.targets.map((target, i) => {
          const host = isHostname(target.ip);
          const addresses = host ? resolved[target.ip] : undefined;
          // Numbers stay in the monospace line; words ("same port") get their own line.
          const port = remote.error
            ? "?"
            : value.port_mode === "same"
              ? spans.length === 1
                ? spanText(spans[0])
                : ""
              : value.port_mode === "map"
                ? remote.spans.length === 1
                  ? spanText(remote.spans[0])
                  : ""
                : String(target.port || "—");
          const portWords = port ? "" : t(value.port_mode === "same" ? "portModeSameShort" : "routeMapped");
          return (
            <li key={i} className="route-target">
              <span className="route-index">{i + 1}</span>
              <div className="min-w-0 flex-1">
                <p className="flex min-w-0 items-center gap-1 font-mono text-sm" dir="ltr">
                  {host && <Globe className="size-3.5 shrink-0 text-primary-text" aria-hidden />}
                  <span className="truncate">{target.ip || "—"}</span>
                  {port && <span className="shrink-0 text-muted-foreground">:{port}</span>}
                </p>
                {portWords && <p className="text-xs text-muted-foreground">{t("remotePort")}: {portWords}</p>}
                {host && (
                  <p className="truncate text-xs text-muted-foreground" dir="ltr">
                    {addresses === undefined ? t("routeResolving") : addresses.length ? addresses.join(", ") : t("dnsNoAddress")}
                  </p>
                )}
                {value.targets.length > 1 && (
                  <p className="text-xs text-muted-foreground">
                    {t("weight")} {number(target.weight, locale)}
                  </p>
                )}
              </div>
            </li>
          );
        })}
      </ol>
      <ul className="route-badges">
        <li data-on={monitored || undefined}>
          <HeartPulse aria-hidden />
          {t(monitored ? "routeMonitored" : "routeNotMonitored")}
        </li>
        {monitored && protection.failover && value.targets.length > 1 && kernel && (
          <li data-on>
            <ShieldCheck aria-hidden />
            {t("protectFailover")}
          </li>
        )}
        {safeMinutes > 0 && (
          <li data-on>
            <Undo2 aria-hidden />
            {t("safeApplyMinutes").replace("{n}", String(safeMinutes))}
          </li>
        )}
      </ul>
    </aside>
  );
}
