// Optimization → DNS: the resolvers this server itself uses. Presets
// (international and Iranian) or manual servers, a speed test from the
// server, apply that survives reboots, and restore of the original.
import { useContext, useMemo, useState } from "react";
import {
  CheckCircle2,
  Gauge,
  Globe2,
  Loader2,
  RotateCcw,
  ServerCog,
  Zap,
} from "lucide-react";
import type { ReactNode } from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { HelpTip } from "@/components/help";
import { PageTitle } from "@/components/shared";
import { Segmented } from "@/components/Segmented";
import { Confirm, type ConfirmRequest } from "@/features/maintenance/Confirm";
import { api } from "@/lib/api";
import { LocaleContext, useT } from "@/lib/i18n";
import { number } from "@/lib/format";
import { useLoaded } from "@/features/operations/hooks";

type Preset = {
  id: string;
  name: string;
  group: "global" | "iran";
  servers: string[];
  ipv6: string[];
};
type ServerDNSView = {
  mode: "resolved" | "file" | "resolvconf" | "networkmanager" | "unknown";
  managed: boolean;
  current: string[];
  upstream: string[];
  active?: string[];
  servers: string[];
  original: string[];
  presets: Preset[];
};
type Probe = {
  server: string;
  ok: number;
  tried: number;
  rtt_ms: number;
  error?: string;
};

const ipv4 =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const usable = (s: string) =>
  (ipv4.test(s) && !/^(0|127)\./.test(s)) ||
  (/^[0-9a-f:]+$/i.test(s) && s.includes(":") && !/^(::1?|fe[89ab])/i.test(s));

function Latency({ probe }: { probe?: Probe }) {
  const t = useT(),
    locale = useContext(LocaleContext);
  if (!probe)
    return <span className="dns-latency text-muted-foreground">—</span>;
  if (!probe.ok)
    return (
      <span className="dns-latency" data-state="bad">
        {t("dnsTestFailed")}
      </span>
    );
  const state = probe.rtt_ms < 40 ? "good" : probe.rtt_ms < 120 ? "ok" : "slow";
  return (
    <span className="dns-latency" data-state={state}>
      <span
        className="dns-latency-bar"
        style={{ inlineSize: `${Math.min(100, (probe.rtt_ms / 200) * 100)}%` }}
        aria-hidden
      />
      <bdi>
        {t("msValue").replace("{n}", number(Math.round(probe.rtt_ms), locale))}
      </bdi>
      {probe.ok < probe.tried && (
        <span className="text-muted-foreground">
          {" "}
          · {probe.ok}/{probe.tried}
        </span>
      )}
    </span>
  );
}

export function ServerDNS({
  run,
  tabs,
}: {
  run: (request: unknown) => Promise<void>;
  tabs: ReactNode;
}) {
  const t = useT();
  const {
    value: view,
    error,
    reload,
  } = useLoaded<ServerDNSView>("dns", () => 0);
  const [group, setGroup] = useState<"global" | "iran" | "manual">("global");
  const [choice, setChoice] = useState<string>();
  const [ipv6, setIPv6] = useState(false);
  const [manual, setManual] = useState("");
  const [probes, setProbes] = useState<Record<string, Probe>>({});
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<ConfirmRequest>();
  const presets = useMemo(() => view?.presets ?? [], [view]);
  const preset = presets.find((p) => p.id === choice);
  const manualList = manual.split(/[\s,]+/).filter(Boolean);
  const manualBad = manualList.filter((s) => !usable(s));
  const servers =
    group === "manual"
      ? manualList.slice(0, 4)
      : preset
        ? [...preset.servers, ...(ipv6 ? preset.ipv6 : [])].slice(0, 4)
        : [];
  const supported = view?.mode === "resolved" || view?.mode === "file";
  const inUse = view
    ? view.mode === "resolved"
      ? (view.active ?? [])
      : view.current
    : [];
  // The fastest preset: best median latency of its first server.
  const fastest = useMemo(() => {
    let best: { id: string; rtt: number } | undefined;
    for (const p of presets.filter((x) => x.group === group)) {
      const probe = probes[p.servers[0]];
      if (probe?.ok && (!best || probe.rtt_ms < best.rtt))
        best = { id: p.id, rtt: probe.rtt_ms };
    }
    return best?.id;
  }, [presets, probes, group]);

  async function test(list?: string[]) {
    setTesting(true);
    setTestError("");
    try {
      const out = await api<Probe[]>("dns/test", { servers: list ?? [] });
      setProbes((current) => ({
        ...current,
        ...Object.fromEntries(out.map((p) => [p.server, p])),
      }));
    } catch (e) {
      setTestError(e instanceof Error ? e.message : String(e));
    } finally {
      setTesting(false);
    }
  }
  async function change(request: unknown) {
    setBusy(true);
    try {
      await run(request);
    } finally {
      setBusy(false);
      await reload();
    }
  }
  const apply = () =>
    setConfirm({
      title: t("dnsApplyTitle"),
      body: t(
        view?.mode === "resolved" ? "dnsApplyResolved" : "dnsApplyFile",
      ).replace("{s}", servers.join(", ")),
      action: t("dnsApply"),
      run: () => change({ action: "dns-apply", dns: { servers } }),
    });
  const restore = () =>
    setConfirm({
      title: t("dnsRestoreTitle"),
      body: t("dnsRestoreBody").replace(
        "{s}",
        view?.original.join(", ") || t("dnsOriginalUnknown"),
      ),
      action: t("dnsRestore"),
      destructive: true,
      run: () => change({ action: "dns-restore" }),
    });

  return (
    <div className="page-stack">
      <PageTitle title={t("optimize")} description={t("optimizeIntro")} />
      {tabs}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <div className="dns-layout">
        <Card className="dns-current">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ServerCog className="size-4" aria-hidden />
              {t("dnsCurrent")}
              <HelpTip label={t("dnsCurrent")}>
                {t("dnsPersistHelp")}
                {view?.mode === "resolved" && <> {t("dnsStubHelp")}</>}
              </HelpTip>
            </CardTitle>
            <CardDescription>
              {view ? t(`dnsMode_${view.mode}`) : t("loading")}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <p className="text-xs text-muted-foreground">
              {t(view?.mode === "resolved" ? "dnsActiveGlobal" : "dnsCurrent")}
            </p>
            <ul className="flex flex-wrap gap-2" dir="ltr">
              {inUse.length ? (
                inUse.map((s) => (
                  <li key={s}>
                    <Badge variant="outline" className="font-mono">
                      {s}
                    </Badge>
                  </li>
                ))
              ) : (
                <li className="text-sm text-muted-foreground">—</li>
              )}
            </ul>
            {view?.managed && (
              <div className="flex flex-col gap-1 text-sm">
                <span className="text-muted-foreground">
                  {t("dnsConfiguredServers")}
                </span>
                <bdi dir="ltr" className="break-words font-mono text-xs">
                  {view.servers.join(", ") || "—"}
                </bdi>
              </div>
            )}
            {view?.managed ? (
              <div className="flex flex-col gap-2">
                <p className="flex items-center gap-1.5 text-sm text-success-text">
                  <CheckCircle2 className="size-4" aria-hidden />
                  {t("dnsManaged")}
                </p>
                <p className="text-xs text-muted-foreground">
                  {t("dnsOriginal")}:{" "}
                  <bdi dir="ltr">
                    {view.original.join(", ") || t("dnsOriginalUnknown")}
                  </bdi>
                </p>
                <Button
                  variant="outline"
                  size="sm"
                  className="self-start"
                  disabled={busy}
                  onClick={restore}
                >
                  <RotateCcw data-icon="inline-start" />
                  {t("dnsRestore")}
                </Button>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">
                {t("dnsNotManaged")}
              </p>
            )}
            {view && !supported && (
              <Alert>
                <AlertDescription>
                  {t(`dnsUnsupported_${view.mode}`)}
                </AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="min-w-0">
                <CardTitle className="flex items-center gap-2">
                  <Globe2 className="size-4" aria-hidden />
                  {t("dnsChoose")}
                  <HelpTip label={t("dnsChoose")}>{t("dnsChooseHelp")}</HelpTip>
                </CardTitle>
              </div>
              <Button
                variant="outline"
                size="sm"
                disabled={testing}
                onClick={() => void test()}
              >
                {testing ? (
                  <Loader2 data-icon="inline-start" className="animate-spin" />
                ) : (
                  <Gauge data-icon="inline-start" />
                )}
                {t(testing ? "dnsTesting" : "dnsTestAll")}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <Segmented
              label={t("dnsChoose")}
              value={group}
              onChange={(v) => setGroup(v as typeof group)}
              options={[
                { value: "global", label: t("dnsGroupGlobal") },
                { value: "iran", label: t("dnsGroupIran") },
                { value: "manual", label: t("dnsGroupManual") },
              ]}
            />
            {testError && (
              <Alert variant="destructive">
                <AlertDescription>{testError}</AlertDescription>
              </Alert>
            )}
            {group === "manual" ? (
              <div className="flex flex-col gap-2">
                <label htmlFor="dns-manual" className="text-sm font-medium">
                  {t("dnsManualLabel")}
                </label>
                <textarea
                  id="dns-manual"
                  dir="ltr"
                  rows={3}
                  className="dns-textarea"
                  placeholder={"1.1.1.1\n8.8.8.8"}
                  value={manual}
                  onChange={(e) => setManual(e.target.value)}
                  aria-invalid={
                    manualBad.length > 0 || manualList.length > 4 || undefined
                  }
                />
                <p
                  className={
                    manualBad.length || manualList.length > 4
                      ? "text-xs text-destructive"
                      : "text-xs text-muted-foreground"
                  }
                >
                  {manualBad.length
                    ? t("dnsManualBad").replace("{s}", manualBad.join(", "))
                    : manualList.length > 4
                      ? t("dnsManualTooMany")
                      : t("dnsManualHelp")}
                </p>
                {manualList.length > 0 && !manualBad.length && (
                  <div className="flex flex-col gap-1.5">
                    {manualList.slice(0, 4).map((s) => (
                      <div key={s} className="dns-row" data-static>
                        <bdi dir="ltr" className="font-mono text-sm">
                          {s}
                        </bdi>
                        <Latency probe={probes[s]} />
                      </div>
                    ))}
                    <Button
                      variant="ghost"
                      size="sm"
                      className="self-start"
                      disabled={testing}
                      onClick={() => void test(manualList.slice(0, 4))}
                    >
                      <Gauge data-icon="inline-start" />
                      {t("dnsTestThese")}
                    </Button>
                  </div>
                )}
              </div>
            ) : (
              <div
                className="flex flex-col gap-1.5"
                role="radiogroup"
                aria-label={t("dnsChoose")}
              >
                {presets
                  .filter((p) => p.group === group)
                  .map((p) => (
                    <label
                      key={p.id}
                      className="dns-row"
                      data-checked={choice === p.id || undefined}
                    >
                      <input
                        type="radio"
                        name="dns-preset"
                        className="sr-only"
                        checked={choice === p.id}
                        onChange={() => setChoice(p.id)}
                      />
                      <span className="dns-radio" aria-hidden />
                      <span className="min-w-0 flex-1">
                        <span className="flex items-center gap-2 text-sm font-medium">
                          {p.name}
                          {fastest === p.id && (
                            <Badge className="gap-1" variant="secondary">
                              <Zap className="size-3" aria-hidden />
                              {t("dnsFastest")}
                            </Badge>
                          )}
                          {view?.managed &&
                            p.servers.every((s) =>
                              view.servers.includes(s),
                            ) && (
                              <Badge variant="outline">{t("dnsInUse")}</Badge>
                            )}
                        </span>
                        <bdi
                          dir="ltr"
                          className="block truncate font-mono text-xs text-muted-foreground"
                        >
                          {p.servers.join("  ·  ")}
                        </bdi>
                      </span>
                      <Latency probe={probes[p.servers[0]]} />
                    </label>
                  ))}
                {group === "iran" && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    {t("dnsIranHelp")}
                  </p>
                )}
              </div>
            )}
            {group !== "manual" && preset && preset.ipv6.length > 0 && (
              <label className="flex items-center justify-between gap-3 text-sm">
                {t("dnsAddIPv6")}
                <Switch checked={ipv6} onCheckedChange={setIPv6} />
              </label>
            )}
            <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
              <p className="min-w-0 text-xs text-muted-foreground">
                {servers.length ? (
                  <>
                    {t("dnsWillUse")}{" "}
                    <bdi dir="ltr" className="font-mono">
                      {servers.join(", ")}
                    </bdi>
                  </>
                ) : (
                  t("dnsPickOne")
                )}
              </p>
              <Button
                disabled={
                  !supported ||
                  busy ||
                  !servers.length ||
                  manualBad.length > 0 ||
                  (group === "manual" && manualList.length > 4)
                }
                onClick={apply}
              >
                {busy && (
                  <Loader2 data-icon="inline-start" className="animate-spin" />
                )}
                {t("dnsApply")}
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
      <Confirm request={confirm} onClose={() => setConfirm(undefined)} />
    </div>
  );
}
