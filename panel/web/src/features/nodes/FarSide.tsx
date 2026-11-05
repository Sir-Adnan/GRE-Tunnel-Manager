import { useContext, useEffect, useState } from "react";
import { Gauge, Loader2, Radar } from "lucide-react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { LocaleContext, useT } from "@/lib/i18n";
import { number, trafficBytes } from "@/lib/format";
import { milliseconds, stamp } from "@/features/health/format";
import { Meter } from "@/features/health/Indicators";
import type { Node, ProbeTunnel, SpeedTest } from "./types";

/** Host pressure the Node reported with its probes. */
export function NodePressure({ node }: { node: Node }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const host = node.probes?.report.host;
  if (!host) return null;
  const memory = host.memory_total
    ? (100 * (host.memory_total - host.memory_available)) / host.memory_total
    : undefined;
  const flows =
    host.conntrack_count != null && host.conntrack_max
      ? (100 * host.conntrack_count) / host.conntrack_max
      : undefined;
  const rows = [
    ["nodeCpu", host.cpu_percent, host.cpu_percent == null ? "—" : `${number(host.cpu_percent, locale)}%`],
    ["nodeMemory", memory, host.memory_total ? `${trafficBytes(host.memory_total - host.memory_available, locale)} / ${trafficBytes(host.memory_total, locale)}` : "—"],
    ["nodeFlows", flows, host.conntrack_count == null ? "—" : `${number(host.conntrack_count, locale)} / ${number(host.conntrack_max ?? 0, locale)}`],
  ] as const;
  return (
    <dl className="node-pressure">
      {rows.map(([label, value, text]) => (
        <div key={label}>
          <dt>{t(label)}</dt>
          <dd>
            <bdi dir="ltr">{text}</bdi>
          </dd>
          <Meter value={value} label={t(label)} />
        </div>
      ))}
    </dl>
  );
}

function SpeedRun({ node, tunnel }: { node: Node; tunnel: ProbeTunnel }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [test, setTest] = useState<SpeedTest>();
  const [error, setError] = useState("");
  const running = test && !["done", "failed"].includes(test.state);
  useEffect(() => {
    if (!running || !test) return;
    const timer = window.setInterval(() => {
      api<SpeedTest>(`nodes/speedtest?id=${test.id}`)
        .then(setTest)
        .catch((e) => setError(e instanceof Error ? e.message : String(e)));
    }, 2000);
    return () => window.clearInterval(timer);
  }, [running, test]);
  async function start() {
    setError("");
    try {
      setTest(await api<SpeedTest>("nodes/speedtest", { node: node.id, tunnel: tunnel.id }));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }
  const mbps = (v?: number) =>
    v == null ? "—" : `${number(v, locale)} Mbit/s`;
  return (
    <div className="speed-run">
      <Button variant="outline" size="sm" disabled={Boolean(running)} onClick={() => void start()}>
        {running ? (
          <Loader2 data-icon="inline-start" className="animate-spin" />
        ) : (
          <Gauge data-icon="inline-start" />
        )}
        {running ? t(`speed_${test.state}`) : t("speedRun")}
      </Button>
      {test?.state === "done" && (
        <dl className="speed-result">
          <div>
            <dt>{t("speedUpload")}</dt>
            <dd><bdi dir="ltr">{mbps(test.upload_mbps)}</bdi></dd>
          </div>
          <div>
            <dt>{t("speedDownload")}</dt>
            <dd><bdi dir="ltr">{mbps(test.download_mbps)}</bdi></dd>
          </div>
        </dl>
      )}
      {(error || test?.state === "failed") && (
        <p className="text-xs text-destructive">{error || test?.error}</p>
      )}
    </div>
  );
}

/** GRE tunnels checked from the Node's side, with an on-demand speed test. */
export function FarSide({ node }: { node: Node }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const report = node.probes?.report;
  if (!report)
    return <p className="text-sm text-muted-foreground">{t("farSideNone")}</p>;
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        {t("farSideIntro")}{" "}
        <span className="whitespace-nowrap">
          {t("farSideAt").replace("{t}", stamp(node.probes?.seen, locale))}
        </span>
      </p>
      <NodePressure node={node} />
      {report.tunnels.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("farSideNoTunnels")}</p>
      ) : (
        <ul className="far-list">
          {report.tunnels.map((tunnel) => (
            <li key={tunnel.id} className="far-row" data-ok={tunnel.ok}>
              <Radar className="size-4 shrink-0 text-muted-foreground" aria-hidden />
              <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                <span className="flex flex-wrap items-center gap-2">
                  <code dir="ltr" className="text-xs font-medium">{tunnel.id}</code>
                  <span className="status-pill" data-status={tunnel.ok ? "up" : "down"}>
                    <span className="status-pill-dot" aria-hidden />
                    {tunnel.ok ? t("farSideAnswers") : t("farSideSilent")}
                  </span>
                  {!tunnel.up && <span className="text-xs text-destructive">{t("farSideIfaceDown")}</span>}
                </span>
                <span className="text-xs text-muted-foreground">
                  <bdi dir="ltr">
                    {tunnel.address} → {tunnel.peer} · {tunnel.local} ⇄ {tunnel.remote}
                  </bdi>
                  {tunnel.rtt_ms != null && (
                    <> · <bdi dir="ltr">{milliseconds(tunnel.rtt_ms, locale)}</bdi></>
                  )}
                </span>
              </div>
              {!node.local && <SpeedRun node={node} tunnel={tunnel} />}
            </li>
          ))}
        </ul>
      )}
      <p className="text-xs text-muted-foreground">{t("speedHelp")}</p>
    </div>
  );
}
