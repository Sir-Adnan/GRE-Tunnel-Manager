// Dashboard header: which server this is, that it is up and for how long,
// and its addresses (the main one copyable at once, the rest in a list).
import { useContext } from "react";
import { Clock3, Copy, Plus, Search } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Address } from "@/components/shared";
import { copyText } from "@/lib/clipboard";
import { number, uptime } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import type { Inventory } from "@/lib/api";

export function HostHeader({
  host,
  add,
  navigate,
}: {
  host: Inventory["host"];
  add: () => void;
  navigate: (page: string) => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const addresses = [...new Set([host.public_ip, ...host.addresses])].filter(
    (ip): ip is string => Boolean(ip),
  );
  const copy = async (text: string) => {
    if (await copyText(text)) toast.success(`${t("copied")}: ${text}`);
    else toast.error(t("copyFailed"));
  };
  return (
    <header className="overview-header">
      <div className="flex min-w-0 flex-col gap-2">
        <p className="eyebrow">{t("overview")}</p>
        <h1 className="page-title">
          <bdi>{host.hostname}</bdi>
        </h1>
        <div className="host-meta">
          <span className="host-meta-item">
            <span className="live-dot" aria-hidden />
            {t("online")}
          </span>
          <span className="host-meta-item">
            <bdi>{host.os}</bdi>
          </span>
          <span className="host-meta-item" title={t("uptime")}>
            <Clock3 aria-hidden />
            <bdi>{uptime(host.uptime, locale)}</bdi>
            {host.load && (
              <span className="text-muted-foreground/80">
                · {t("load")} <bdi dir="ltr">{host.load}</bdi>
              </span>
            )}
          </span>
          {addresses[0] && (
            <span className="host-meta-item is-address">
              <Address>{addresses[0]}</Address>
              {addresses.length > 1 && (
                <Popover>
                  <PopoverTrigger asChild>
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-label={t("dashAddresses")}
                    >
                      <Badge variant="secondary">
                        <bdi>+{number(addresses.length - 1, locale)}</bdi>
                      </Badge>
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent
                    align="start"
                    className="w-72 max-w-[calc(100vw-2rem)] gap-2 p-3"
                  >
                    <p className="text-sm font-medium">{t("dashAddresses")}</p>
                    <ul className="flex flex-col gap-0.5">
                      {addresses.map((ip) => (
                        <li
                          key={ip}
                          className="flex items-center justify-between gap-2"
                        >
                          <bdi dir="ltr" className="truncate font-mono text-xs">
                            {ip}
                          </bdi>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label={`${t("copy")} ${ip}`}
                            onClick={() => void copy(ip)}
                          >
                            <Copy />
                          </Button>
                        </li>
                      ))}
                    </ul>
                  </PopoverContent>
                </Popover>
              )}
            </span>
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
  );
}
