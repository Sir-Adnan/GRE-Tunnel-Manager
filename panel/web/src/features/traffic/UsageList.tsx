import { useContext, useState } from "react";
import { ArrowUpRight, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { FieldGroup } from "@/components/ui/field";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import {
  Table,
  TableHeader,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
} from "@/components/ui/table";
import { TextField, Choice } from "@/components/shared";
import { ActionButton, HelpTip } from "@/components/help";
import type { Inventory, Metrics, TrafficPolicy } from "@/lib/api";
import { LocaleContext, useT } from "@/lib/i18n";
import { engineName, trafficBytes } from "@/lib/format";
import { cycleUsage, quotaUsage } from "./accounting";
import { TrafficActions } from "./TrafficActions";

type UsageRow = {
  id: string;
  resource?: { name: string; engine: string; port: string };
  counter?: Metrics["counters"][string];
  policy?: TrafficPolicy;
};

export function UsageList(p: {
  rows: UsageRow[];
  inventory: Inventory;
  metrics?: Metrics;
  busy: boolean;
  run: (r: unknown) => Promise<void>;
  refresh: () => Promise<void>;
  query: string;
  onQuery: (v: string) => void;
  engine: string;
  onEngine: (v: string) => void;
  onDetails: (id: string) => void;
  onExport: () => void;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const [page, setPage] = useState(0);
  const pageSize = 20;
  const pages = Math.max(1, Math.ceil(p.rows.length / pageSize));
  const current = Math.min(page, pages - 1);
  const visible = p.rows.slice(current * pageSize, (current + 1) * pageSize);
  const bytes = (row: UsageRow, direction: "received" | "sent" | "total") => {
    if (!row.counter) return "—";
    const v = cycleUsage(row.counter);
    return trafficBytes(
      direction === "total" ? v.received + v.sent : v[direction],
      locale,
    );
  };
  const actions = (row: UsageRow) => (
    <div className="flex items-center justify-end gap-1">
      <ActionButton
        label={`${t("viewUsage")} ${row.resource?.name || row.id}`}
        variant="ghost"
        size="icon"
        onClick={() => p.onDetails(row.id)}
      >
        <ArrowUpRight />
      </ActionButton>
      <TrafficActions
        compact
        id={row.id}
        name={row.resource?.name || row.id}
        removed={!row.resource}
        connection={p.inventory.connections.find((c) => c.id === row.id)}
        policy={row.policy}
        revision={p.metrics?.revision}
        disabled={p.busy}
        run={p.run}
        refresh={p.refresh}
      />
    </div>
  );
  const identity = (row: UsageRow) => (
    <div className="flex min-w-0 flex-col gap-1">
      <span className="break-words font-medium">
        {row.resource?.name || row.id}
      </span>
      <span className="text-xs text-muted-foreground">
        <bdi>{engineName(row.resource?.engine || "archived")}</bdi>
        {row.resource?.port && (
          <>
            {" "}
            · <bdi dir="ltr">{row.resource.port}</bdi>
          </>
        )}
        {row.policy?.label && <> · {row.policy.label}</>}
      </span>
    </div>
  );
  const quota = (row: UsageRow) =>
    row.policy?.limit ? (
      <Badge variant="outline">
        {t(
          quotaUsage(row.counter, row.policy).reached
            ? "quotaReached"
            : "withinQuota",
        )}
      </Badge>
    ) : (
      <span className="text-xs text-muted-foreground">{t("noQuota")}</span>
    );
  return (
    <Card className="@container min-w-0">
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-1">
            <CardTitle>{t("allUsage")}</CardTitle>
            <HelpTip>{t("usageListHelp")}</HelpTip>
          </div>
          <Button
            variant="outline"
            onClick={p.onExport}
            disabled={!p.rows.length}
          >
            <Download data-icon="inline-start" />
            {t("exportCSV")}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        <FieldGroup columns className="max-w-2xl">
          <TextField
            id="usage-search"
            label={t("search")}
            placeholder={t("usageSearch")}
            value={p.query}
            onChange={(e) => {
              p.onQuery(e.target.value);
              setPage(0);
            }}
          />
          <Choice
            id="usage-engine"
            label={t("method")}
            value={p.engine}
            onChange={(v) => {
              p.onEngine(v);
              setPage(0);
            }}
            choices={[
              { value: "all", label: t("allMethods") },
              ...[
                "haproxy",
                "realm",
                "nftables",
                "iptables",
                "gre",
                "frp",
                "rathole",
              ].map((e) => ({ value: e, label: engineName(e) })),
            ]}
          />
        </FieldGroup>
        <div className="hidden @3xl:block">
          <Table className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className="w-[30%]">{t("name")}</TableHead>
                <TableHead>{t("received")}</TableHead>
                <TableHead>{t("sent")}</TableHead>
                <TableHead>{t("total")}</TableHead>
                <TableHead>{t("cycleQuota")}</TableHead>
                <TableHead className="w-24">{t("actions")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {visible.map((row) => (
                <TableRow key={row.id}>
                  <TableCell>{identity(row)}</TableCell>
                  {(["received", "sent", "total"] as const).map((k) => (
                    <TableCell key={k}>
                      <bdi className="tabular-nums">{bytes(row, k)}</bdi>
                    </TableCell>
                  ))}
                  <TableCell>{quota(row)}</TableCell>
                  <TableCell>{actions(row)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <div className="flex flex-col divide-y @3xl:hidden">
          {visible.map((row) => (
            <article
              key={row.id}
              className="flex flex-col gap-3 py-4 first:pt-0"
            >
              <div className="flex items-start justify-between gap-2">
                {identity(row)}
                {actions(row)}
              </div>
              <dl className="grid grid-cols-3 gap-2">
                {(["received", "sent", "total"] as const).map((k) => (
                  <div key={k} className="min-w-0">
                    <dt className="text-xs text-muted-foreground">{t(k)}</dt>
                    <dd className="mt-1 break-words tabular-nums">
                      <bdi>{bytes(row, k)}</bdi>
                    </dd>
                  </div>
                ))}
              </dl>
              {quota(row)}
            </article>
          ))}
        </div>
        {!p.rows.length && (
          <p className="py-6 text-center text-sm text-muted-foreground">
            {t("noTrackableResources")}
          </p>
        )}
        {pages > 1 && (
          <div className="flex items-center justify-between gap-2">
            <bdi>
              {current + 1} / {pages}
            </bdi>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={!current}
                onClick={() => setPage(current - 1)}
              >
                {t("previousPage")}
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={current + 1 === pages}
                onClick={() => setPage(current + 1)}
              >
                {t("nextPage")}
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
