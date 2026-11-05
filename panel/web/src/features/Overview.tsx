import { useContext } from "react";
import {
  Activity,
  CircleAlert,
  Clock3,
  Layers3,
  Plus,
  Search,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Address, EngineGlyph, SectionLink } from "@/components/shared";
import { ConnectionSummary } from "@/features/connections/ConnectionSummary";
import { number, uptime, engineName } from "@/lib/format";
import { attentionItems } from "@/lib/attention";
import { engineCounts } from "@/lib/connection-filters";
import { LiveTelemetry } from "./overview/LiveTelemetry";
import { AttentionPanel } from "./overview/AttentionPanel";
import { LocaleContext, useT } from "@/lib/i18n";
import type { Connection, Inventory } from "@/lib/api";
import { cn } from "@/lib/utils";

function Kpi({
  icon: Icon,
  label,
  value,
  detail,
  tone,
  onClick,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  detail: string;
  tone?: "alert" | "ok";
  onClick?: () => void;
}) {
  const body = (
    <>
      <span className="kpi-label">
        <Icon className="size-4" />
        {label}
      </span>
      <span className="kpi-value">
        <bdi>{value}</bdi>
      </span>
      <span className="kpi-detail">
        <bdi>{detail}</bdi>
      </span>
    </>
  );
  return onClick ? (
    <button
      type="button"
      className={cn("kpi", tone && `is-${tone}`)}
      onClick={onClick}
    >
      {body}
    </button>
  ) : (
    <div className={cn("kpi", tone && `is-${tone}`)}>{body}</div>
  );
}

/** Status first: what runs on this server, what needs attention, and live host load. */
import type { ReactNode } from "react";
import { toast } from "sonner";
import { DragHandle, SortableArea, SortableItem } from "@/components/sortable";
import { applyOrder, useOrder } from "@/lib/order";

const blockNames: Record<string, string> = { kpi: "overviewBlockKpi", status: "overviewBlockStatus", recent: "recent" };

/** The overview's main blocks in the order people set (drag the handle at the side). */
function OverviewBlocks({ blocks }: { blocks: Record<string, ReactNode> }) {
  const t = useT();
  const order = useOrder("overview");
  const ids = applyOrder(Object.keys(blocks), order.ids, (id) => id);
  return (
    <SortableArea
      ids={ids}
      onMove={(next) =>
        void order.save(next).then((e) => {
          if (e) toast.error(t("orderSaveFailed").replace("{e}", e));
        })
      }
    >
      {ids.map((id) => (
        <SortableItem key={id} id={id}>
          {(item) => (
            <section ref={item.setNodeRef} style={item.style} className="overview-block" data-dragging={item.dragging || undefined} aria-label={t(blockNames[id])}>
              <DragHandle handle={item.handle} label={t(blockNames[id])} className="overview-block-handle" />
              {blocks[id]}
            </section>
          )}
        </SortableItem>
      ))}
    </SortableArea>
  );
}

export function Overview({
  inventory,
  add,
  edit,
  navigate,
}: {
  inventory: Inventory;
  add: () => void;
  edit: (value: Connection) => void;
  navigate: (page: string, params?: Record<string, string>) => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const h = inventory.host;
  const issues = attentionItems(inventory);
  const services = [
    ...inventory.connections.filter((c) => c.enabled),
    ...inventory.resources.filter((r) => r.configured),
  ];
  const running =
    inventory.connections.filter((c) =>
      ["active", "configured"].includes(c.status || ""),
    ).length + inventory.resources.filter((r) => r.status === "active").length;
  const counts = engineCounts(inventory.connections);
  const addresses = [...new Set([h.public_ip, ...h.addresses])].filter(
    (ip): ip is string => Boolean(ip),
  );
  return (
    <div className="page-stack">
      <header className="overview-header">
        <div className="flex min-w-0 flex-col gap-2">
          <p className="eyebrow">{t("overview")}</p>
          <h1 className="page-title">
            <bdi>{h.hostname}</bdi>
          </h1>
          <div className="host-meta">
            <span className="flex items-center gap-1.5">
              <span className="live-dot" aria-hidden />
              {t("online")}
            </span>
            <span aria-hidden>·</span>
            <bdi>{h.os}</bdi>
            {addresses[0] && (
              <>
                <span aria-hidden className="hidden sm:inline">
                  ·
                </span>
                <Address>{addresses[0]}</Address>
                {addresses.length > 1 && (
                  <span className="text-xs text-muted-foreground">
                    +{number(addresses.length - 1, locale)}
                  </span>
                )}
              </>
            )}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            onClick={() => navigate("connections")}
            className="hidden sm:inline-flex"
          >
            <Search data-icon="inline-start" />
            {t("seeAll")}
          </Button>
          <Button onClick={add}>
            <Plus data-icon="inline-start" />
            {t("newConnection")}
          </Button>
        </div>
      </header>
      <OverviewBlocks
        blocks={{
          kpi: (
      <div className="kpi-grid">
        <Kpi
          icon={Layers3}
          label={t("managed")}
          value={number(inventory.connections.length, locale)}
          detail={`${number(inventory.connections.filter((c) => c.enabled).length, locale)} ${t("configured")}`}
          onClick={() => navigate("connections")}
        />
        <Kpi
          icon={Activity}
          label={t("services")}
          value={`${number(running, locale)} / ${number(services.length, locale)}`}
          detail={t("servicesRunning")}
        />
        <Kpi
          icon={CircleAlert}
          label={t("needsAttention")}
          value={number(issues.length, locale)}
          detail={t(issues.length ? "reviewIssues" : "allHealthy")}
          tone={issues.length ? "alert" : "ok"}
        />
        <Kpi
          icon={Clock3}
          label={t("uptime")}
          value={uptime(h.uptime, locale)}
          detail={h.load ? `${t("load")} ${h.load}` : h.os}
        />
      </div>
          ),
          status: (
      <div className="overview-grid">
        <LiveTelemetry />
        <AttentionPanel items={issues} navigate={navigate} />
      </div>
          ),
          recent: (
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <CardTitle>{t("recent")}</CardTitle>
            <div className="flex flex-wrap items-center gap-1">
              {(["haproxy", "realm", "kernel"] as const)
                .filter((id) => counts[id])
                .map((id) => (
                  <Button
                    key={id}
                    size="sm"
                    variant="ghost"
                    onClick={() => navigate("connections", { engine: id })}
                  >
                    <EngineGlyph engine={id === "kernel" ? "nftables" : id} />
                    {id === "kernel" ? t("forwarding") : engineName(id)}
                    <span className="text-muted-foreground tabular-nums">
                      {number(counts[id], locale)}
                    </span>
                  </Button>
                ))}
              <SectionLink onClick={() => navigate("connections")}>
                {t("seeAll")}
              </SectionLink>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <ConnectionSummary
            connections={inventory.connections}
            onAdd={add}
            onEdit={edit}
          />
        </CardContent>
      </Card>
          ),
        }}
      />
    </div>
  );
}
