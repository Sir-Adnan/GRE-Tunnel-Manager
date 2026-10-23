import { useCallback, useContext, useEffect, useRef, useState } from "react";
import { RefreshCw } from "lucide-react";
import { api } from "@/lib/api";
import { LocaleContext, useT } from "@/lib/i18n";
import { engineName, trafficBytes } from "@/lib/format";
import { ActionButton, HelpTip } from "@/components/help";
import { TextField } from "@/components/shared";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import {
  Empty,
  EmptyHeader,
  EmptyTitle,
  EmptyDescription,
} from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import type { Node, NodeTrafficView } from "./types";

export function NodeTraffic({ node }: { node: Node }) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const [view, setView] = useState<NodeTrafficView>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState("");
  const lifetime = useRef<AbortController | null>(null);
  const latest = useRef(0);
  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      if (!signal || signal.aborted) return;
      const request = ++latest.current;
      setLoading(true);
      try {
        const value = await api<NodeTrafficView>(
          `nodes/traffic?id=${encodeURIComponent(node.id)}`,
        );
        if (!signal.aborted && request === latest.current) {
          setView(value);
          setError("");
        }
      } catch (e) {
        if (!signal.aborted && request === latest.current) setError(String(e));
      } finally {
        if (!signal.aborted && request === latest.current) setLoading(false);
      }
    },
    [node.id],
  );
  useEffect(() => {
    const controller = new AbortController();
    lifetime.current = controller;
    const reload = () => {
      if (!document.hidden) void refresh(controller.signal);
    };
    reload();
    const timer = window.setInterval(reload, 60000);
    document.addEventListener("visibilitychange", reload);
    return () => {
      controller.abort();
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", reload);
    };
  }, [refresh]);
  const summary = view?.node_id === node.id ? view.summary : undefined;
  const date = (s?: string) =>
    s && Date.parse(s) > 0
      ? new Date(s).toLocaleString(
          locale === "fa" ? "fa-IR-u-nu-latn" : "en-US",
        )
      : "—";
  const resources = [
    ...(node.inventory?.connections.map((c) => ({
      id: c.id,
      name: c.name,
      engine: c.engine,
      port: c.ports,
    })) || []),
    ...(node.inventory?.resources.map((r) => ({
      id: r.id,
      name: r.name,
      engine: r.engine,
      port: r.port ? String(r.port) : r.interface || "",
    })) || []),
  ];
  const rows = Object.entries(summary?.counters || {})
    .map(([id, c]) => ({ id, c, resource: resources.find((r) => r.id === id) }))
    .filter((r) =>
      `${r.resource?.name || r.id} ${r.resource?.port || ""}`
        .toLocaleLowerCase()
        .includes(query.toLocaleLowerCase()),
    );
  return (
    <section
      className="flex min-w-0 flex-col gap-4"
      aria-label={t("nodeTraffic")}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Badge variant="outline">{t("readOnly")}</Badge>
          {summary && (
            <Badge variant="secondary">
              {t(summary.enabled ? "collecting" : "collectionPaused")}
            </Badge>
          )}
          <HelpTip label={t("help")}>{t("nodeTrafficHelp")}</HelpTip>
        </div>
        <ActionButton
          label={t("refresh")}
          variant="outline"
          size="icon-sm"
          disabled={loading}
          onClick={() => void refresh(lifetime.current?.signal)}
        >
          <RefreshCw />
        </ActionButton>
      </div>
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {view?.observed && (
        <p className="text-xs text-muted-foreground">
          {t("nodeTrafficObserved")} · <bdi>{date(view.observed)}</bdi>
        </p>
      )}
      {(view?.status === "offline" ||
        view?.status === "degraded" ||
        summary?.failure) && (
        <Alert>
          <AlertDescription>{t("nodeTrafficStale")}</AlertDescription>
        </Alert>
      )}
      {!view && !error && <Skeleton className="h-32 w-full" />}
      {view?.status === "revoked" ? (
        <Alert>
          <AlertDescription>{t("node_revoked")}</AlertDescription>
        </Alert>
      ) : view && !summary ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>{t("nodeTrafficWaiting")}</EmptyTitle>
            <EmptyDescription>{t("nodeTrafficSetup")}</EmptyDescription>
          </EmptyHeader>
          <code dir="ltr" className="code-block w-full overflow-auto text-xs">
            sudo bash node-install.sh --agent --traffic --package-dir
            /path/to/packages
          </code>
          <code dir="ltr" className="code-block w-full overflow-auto text-xs">
            sudo gtm-panel nodes traffic --enable --interval 60
          </code>
        </Empty>
      ) : (
        summary && (
          <>
            <TextField
              id={`traffic-search-${node.id}`}
              label={t("search")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            {!rows.length && (
              <Empty>
                <EmptyHeader>
                  <EmptyTitle>
                    {t(query ? "noMatch" : "nodeTrafficNoSamples")}
                  </EmptyTitle>
                  {!query && (
                    <EmptyDescription>{t("nodeTrafficEmpty")}</EmptyDescription>
                  )}
                </EmptyHeader>
              </Empty>
            )}
            {rows.map(({ id, c, resource }) => (
              <Card key={id} className="min-w-0">
                <CardHeader>
                  <CardTitle className="break-words">
                    {resource?.name || id}
                  </CardTitle>
                  <div className="flex flex-wrap gap-2">
                    <Badge variant="outline">
                      {resource
                        ? engineName(resource.engine)
                        : t("nodeTrafficUnknown")}
                    </Badge>
                    {resource?.port && (
                      <Badge variant="outline">
                        <bdi>{resource.port}</bdi>
                      </Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent>
                  <p className="mb-3 text-xs text-muted-foreground">
                    {t("nodeTrafficCurrent")}
                  </p>
                  <dl className="grid grid-cols-2 gap-4">
                    <div>
                      <dt className="text-xs text-muted-foreground">
                        {t("received")}
                      </dt>
                      <dd className="mt-1 font-mono text-lg">
                        <bdi dir="ltr">
                          {trafficBytes(c.cycle_received, locale)}
                        </bdi>
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs text-muted-foreground">
                        {t("sent")}
                      </dt>
                      <dd className="mt-1 font-mono text-lg">
                        <bdi dir="ltr">
                          {trafficBytes(c.cycle_sent, locale)}
                        </bdi>
                      </dd>
                    </div>
                  </dl>
                  <p className="mt-4 text-xs text-muted-foreground">
                    {t("lifetimeUsage")} ·{" "}
                    <bdi dir="ltr">
                      {trafficBytes(c.received, locale)} /{" "}
                      {trafficBytes(c.sent, locale)}
                    </bdi>
                  </p>
                </CardContent>
                <CardFooter className="flex flex-col items-start gap-1 text-xs text-muted-foreground">
                  <span>
                    {t("nodeTrafficSample")} · <bdi>{date(c.updated)}</bdi>
                  </span>
                  <span>
                    {t("nodeTrafficCycle")} · <bdi>{date(c.cycle_start)}</bdi>
                  </span>
                </CardFooter>
              </Card>
            ))}
          </>
        )
      )}
    </section>
  );
}
