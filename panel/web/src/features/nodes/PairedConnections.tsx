import { useCallback, useContext, useEffect, useState } from "react";
import { ArrowLeftRight, RefreshCw } from "lucide-react";
import { api } from "@/lib/api";
import { LocaleContext, useT } from "@/lib/i18n";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import type { Node } from "./types";
import { PairForm } from "./PairForm";

type Result = { state: string; code?: string };
type Pair = {
  id: string;
  name: string;
  kind: string;
  revision: string;
  state: string;
  steps: {
    node: string;
    service: string;
    stage: string;
    result?: Result;
    deadline?: string;
  }[];
};
const finished = (p: Pair) =>
  ["succeeded", "rolled_back", "needs_attention"].includes(p.state);
export function PairedConnections({ nodes }: { nodes: Node[] }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [pairs, setPairs] = useState<Pair[]>([]);
  const [error, setError] = useState("");
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const choices = nodes.filter(
    (n) =>
      n.status === "online" && n.capabilities.includes("connections.pair.v1"),
  );
  const nodeName = (id: string) => nodes.find((n) => n.id === id)?.name || id;
  const refresh = useCallback(async () => {
    setPairs(await api<Pair[]>("nodes/pairs"));
  }, []);
  useEffect(() => {
    const reload = () => {
      void refresh().catch((e) => setError(String(e)));
    };
    reload();
    window.addEventListener("gtm:nodes-refresh", reload);
    return () => window.removeEventListener("gtm:nodes-refresh", reload);
  }, [refresh]);
  const active = pairs.some((p) => !finished(p));
  useEffect(() => {
    if (!active) return;
    let pending = false;
    const reload = () => {
      if (document.hidden || pending) return;
      pending = true;
      void refresh()
        .catch((e) => setError(String(e)))
        .finally(() => {
          pending = false;
        });
    };
    const timer = setInterval(reload, 2000);
    document.addEventListener("visibilitychange", reload);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", reload);
    };
  }, [active, refresh]);
  async function perform(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("pairedConnections")}</CardTitle>
        <CardDescription>{t("pairedConnectionsHelp")}</CardDescription>
      </CardHeader>
      <CardContent className="flex min-w-0 flex-col gap-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {!pairs.length && (
          <p className="text-sm text-muted-foreground">{t("noPairJobs")}</p>
        )}
        {[...pairs].reverse().map((p) => (
          <Card key={p.id}>
            <CardHeader>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <CardTitle className="min-w-0 [overflow-wrap:anywhere]">
                  {p.name}
                </CardTitle>
                <Badge variant="outline">{t(`pair_${p.state}`)}</Badge>
              </div>
              <CardDescription>{p.kind.toUpperCase()}</CardDescription>
            </CardHeader>
            <CardContent className="grid min-w-0 gap-4 md:grid-cols-2">
              {p.steps.map((s, i) => (
                <div key={s.node} className="flex min-w-0 flex-col gap-2">
                  <span className="text-sm font-medium [overflow-wrap:anywhere]">
                    {t(i === 0 ? "pairEntrance" : "pairDestination")} ·{" "}
                    <bdi>{nodeName(s.node)}</bdi>
                  </span>
                  <bdi dir="ltr" className="break-all font-mono text-xs">
                    {s.service}
                  </bdi>
                  <span className="text-sm">
                    {t(`pair_${s.result?.state || s.stage}`)}
                  </span>
                  {s.result?.code && (
                    <p className="text-xs text-muted-foreground">
                      {t(`pairCode_${s.result.code}`)}
                    </p>
                  )}
                  {s.deadline && !finished(p) && (
                    <span className="text-xs text-muted-foreground">
                      {t("pairLeaseUntil")} ·{" "}
                      {new Date(s.deadline).toLocaleTimeString(
                        locale === "fa" ? "fa-IR-u-nu-latn" : "en-US",
                      )}
                    </span>
                  )}
                </div>
              ))}
            </CardContent>
            {(!finished(p) || p.state === "needs_attention") && (
              <CardFooter className="flex flex-wrap gap-2">
                {p.state === "awaiting_confirmation" && (
                  <Button
                    disabled={busy}
                    onClick={() =>
                      void perform(async () => {
                        await api("nodes/pairs/decision", {
                          id: p.id,
                          revision: p.revision,
                          decision: "confirm",
                        });
                      })
                    }
                  >
                    {t("pairConfirm")}
                  </Button>
                )}
                <Button
                  variant="outline"
                  disabled={busy || p.state === "rolling_back"}
                  onClick={() =>
                    void perform(async () => {
                      await api("nodes/pairs/decision", {
                        id: p.id,
                        revision: p.revision,
                        decision: "rollback",
                      });
                    })
                  }
                >
                  {t(
                    p.state === "needs_attention"
                      ? "pairRetryRecovery"
                      : "pairRollback",
                  )}
                </Button>
              </CardFooter>
            )}
          </Card>
        ))}
        <Alert>
          <AlertDescription>{t("pairSafetyHelp")}</AlertDescription>
        </Alert>
      </CardContent>
      <CardFooter className="flex flex-wrap gap-2">
        <Button
          onClick={() => setOpen(true)}
          disabled={choices.length < 2 || busy}
        >
          <ArrowLeftRight data-icon="inline-start" />
          {t("pairCreate")}
        </Button>
        <Button
          variant="outline"
          disabled={busy}
          onClick={() => void perform(refresh)}
        >
          <RefreshCw data-icon="inline-start" />
          {t("refresh")}
        </Button>
        {choices.length < 2 && (
          <p className="text-xs text-muted-foreground">{t("pairEnableHelp")}</p>
        )}
      </CardFooter>
      {open && (
        <PairForm
          nodes={nodes}
          onClose={() => setOpen(false)}
          onCreated={() => {
            setOpen(false);
            void perform(refresh);
          }}
        />
      )}
    </Card>
  );
}
