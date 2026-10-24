import { useContext } from "react";
import {
  Activity,
  ArrowUpRight,
  Clock3,
  Layers3,
  MemoryStick,
  Plus,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Address, PageTitle, SectionLink } from "@/components/shared";
import { ConnectionSummary } from "@/features/connections/ConnectionSummary";
import { number, trafficBytes, uptime } from "@/lib/format";
import { LocaleContext } from "@/lib/i18n";
import type { Connection, Inventory } from "@/lib/api";
import { useT } from "@/lib/i18n";

export function Overview({
  inventory,
  add,
  edit,
  navigate,
}: {
  inventory: Inventory;
  add: () => void;
  edit: (value: Connection) => void;
  navigate: (page: string) => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const h = inventory.host;
  const used = h.memory_total - h.memory_available;
  const online =
    inventory.connections.filter((c) => c.status === "active").length +
    inventory.resources.filter((r) => r.status === "active").length;
  const cards = [
    {
      label: "managed",
      value: number(inventory.connections.length, locale),
      extra: `${number(inventory.connections.filter((c) => c.enabled).length, locale)} ${t("configured")}`,
      icon: Layers3,
    },
    {
      label: "services",
      value: number(online, locale),
      extra: "HAProxy · Realm · GRE · Reverse",
      icon: Activity,
    },
    {
      label: "memory",
      value: h.memory_total
        ? `${number(Math.round((used / h.memory_total) * 100), locale)}${locale === "fa" ? "٪" : "%"}`
        : "—",
      extra: `${trafficBytes(used, locale)} / ${trafficBytes(h.memory_total, locale)}`,
      icon: MemoryStick,
    },
    {
      label: "uptime",
      value: uptime(h.uptime, locale),
      extra: h.os,
      icon: Clock3,
    },
  ];
  return (
    <div className="page-stack">
      <PageTitle
        title={t("headline")}
        description={t("subtitle")}
        action={
          <Button size="lg" onClick={add}>
            <Plus data-icon="inline-start" />
            {t("newConnection")}
          </Button>
        }
      />
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span>
          {h.hostname} · {h.os}
        </span>
        {[...new Set([h.public_ip, ...h.addresses].filter(Boolean))]
          .slice(0, 4)
          .map((ip) => (
            <Address key={ip}>{ip!}</Address>
          ))}
      </div>
      <dl className="overview-metrics">
        {cards.map(({ label, value, extra, icon: Icon }) => (
          <div key={label} className="overview-metric">
            <dt className="flex items-center gap-2 text-xs text-muted-foreground">
              <Icon className="size-4" />
              {t(label)}
            </dt>
            <dd className="stat-value">
              <bdi>{value}</bdi>
            </dd>
            <dd className="min-w-0 break-words text-xs text-muted-foreground">
              <bdi>{extra}</bdi>
            </dd>
          </div>
        ))}
      </dl>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3">
            <div className="flex flex-col gap-1">
              <CardTitle>{t("recent")}</CardTitle>
            </div>
            <SectionLink onClick={() => navigate("connections")}>
              {t("seeAll")}
            </SectionLink>
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
      <Card size="sm">
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <CardTitle>{t("components")}</CardTitle>
            <SectionLink onClick={() => navigate("components")}>
              {t("seeAll")}
            </SectionLink>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center gap-2">
            {inventory.components
              .filter((c) => c.installed)
              .map((c) => (
                <Badge key={c.id} variant="outline">
                  {c.id}
                </Badge>
              ))}
            <Button
              size="sm"
              variant="ghost"
              onClick={() => navigate("traffic")}
            >
              {t("traffic")}
              <ArrowUpRight data-icon="inline-end" />
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
