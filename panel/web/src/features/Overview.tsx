import { useContext } from "react";
import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  Clock3,
  Layers3,
  MemoryStick,
  Plus,
  ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Address, PageTitle, SectionLink } from "@/components/shared";
import { ConnectionTable } from "@/features/connections/ConnectionTable";
import { number, trafficBytes, uptime } from "@/lib/format";
import { LocaleContext } from "@/lib/i18n";
import type { Connection, Inventory } from "@/lib/api";
import { useT } from "@/lib/i18n";

export function Overview({
  inventory,
  add,
  edit,
  navigate,
  run,
}: {
  inventory: Inventory;
  add: () => void;
  edit: (value: Connection) => void;
  navigate: (page: string) => void;
  run: (request: unknown) => Promise<void>;
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
      <div className="stats-grid">
        {cards.map(({ label, value, extra, icon: Icon }) => (
          <Card key={label}>
            <CardHeader>
              <CardDescription className="flex items-center gap-2">
                <Icon className="size-4" />
                {t(label)}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="stat-value">{value}</div>
            </CardContent>
            <CardFooter>
              <span className="truncate text-xs text-muted-foreground">
                {extra}
              </span>
            </CardFooter>
          </Card>
        ))}
      </div>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3">
            <div className="flex flex-col gap-1">
              <CardTitle>{t("recent")}</CardTitle>
              <CardDescription>
                GRE · nftables · iptables · HAProxy · Realm
              </CardDescription>
            </div>
            <SectionLink onClick={() => navigate("connections")}>
              {t("seeAll")}
            </SectionLink>
          </div>
        </CardHeader>
        <CardContent>
          <ConnectionTable
            connections={inventory.connections}
            onAdd={add}
            onEdit={edit}
            run={run}
            compact
          />
        </CardContent>
        <CardFooter>
          <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <ArrowDownLeft className="size-3.5" />
              {t("listener")}
            </span>
            <ArrowUpRight className="size-3.5" />
            <span>{t("destination")}</span>
          </div>
        </CardFooter>
      </Card>
      <div className="grid gap-5 lg:grid-cols-[1.6fr_1fr]">
        <Card className="quiet-card">
          <CardHeader>
            <ShieldCheck className="size-6 text-primary" />
            <CardTitle>{t("quiet")}</CardTitle>
            <CardDescription>{t("quietDesc")}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              <Badge variant="outline">Bash + Go</Badge>
              <Badge variant="outline">
                {t("traffic")} · {t("optional")}
              </Badge>
              <Badge variant="outline">
                {location.protocol === "https:" ? "HTTPS" : "HTTP"}
              </Badge>
            </div>
          </CardContent>
          <CardFooter>
            <Button variant="outline" onClick={() => navigate("traffic")}>
              {t("traffic")}
              <ArrowUpRight data-icon="inline-end" />
            </Button>
          </CardFooter>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>{t("components")}</CardTitle>
            <CardDescription>{t("componentsDesc")}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {inventory.components
                .filter((c) => c.installed)
                .map((c) => (
                  <Badge key={c.id} variant="secondary">
                    {c.id}
                  </Badge>
                ))}
            </div>
          </CardContent>
          <CardFooter>
            <Button variant="ghost" onClick={() => navigate("components")}>
              {t("seeAll")}
              <ArrowUpRight data-icon="inline-end" />
            </Button>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}
