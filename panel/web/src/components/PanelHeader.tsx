import { useContext } from "react";
import {
  ChevronRight,
  Globe2,
  Moon,
  Monitor,
  RefreshCw,
  Server,
  Sun,
} from "lucide-react";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { ActionButton } from "@/components/help";
import { Address } from "@/components/shared";
import { AccessStatus } from "@/components/AccessStatus";
import { LocaleContext, useT } from "@/lib/i18n";
import type { Inventory } from "@/lib/api";
import type { Preferences } from "@/features/Settings";

export function PanelHeader({
  page,
  inventory,
  preferences,
  setPreferences,
  busy,
  refresh,
}: {
  page: string;
  inventory?: Inventory;
  preferences: Preferences;
  setPreferences: (value: Preferences) => void;
  busy: boolean;
  refresh: () => void;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const addresses = [
    ...new Set(
      [inventory?.host.public_ip, ...(inventory?.host.addresses || [])].filter(
        (ip): ip is string => Boolean(ip),
      ),
    ),
  ];
  return (
    <header className="topbar">
      <div className="flex min-w-0 items-center gap-2 sm:gap-3">
        <SidebarTrigger aria-label={t("toggleSidebar")} />
        <span className="hidden text-sm text-muted-foreground lg:inline">
          Tunnel Manager
        </span>
        <ChevronRight className="hidden size-3.5 text-muted-foreground rtl:rotate-180 lg:block" />
        <span className="truncate text-sm font-medium">
          {page === "haproxy"
            ? "HAProxy"
            : page === "realm"
              ? "Realm"
              : t(page)}
        </span>
      </div>
      <div className="flex shrink-0 items-center gap-1 sm:gap-2">
        {addresses[0] && (
          <span className="hidden xl:inline-flex">
            <Address>{addresses[0]}</Address>
          </span>
        )}
        <Popover>
          <PopoverTrigger asChild>
            <Button variant="ghost" size="sm" aria-label={t("currentServer")}>
              <Server data-icon="inline-start" />
              <span className="hidden max-w-32 truncate md:inline">
                <bdi>{inventory?.host.hostname || t("currentServer")}</bdi>
              </span>
            </Button>
          </PopoverTrigger>
          <PopoverContent
            align="end"
            className="w-80 max-w-[calc(100vw-2rem)]"
            dir={locale === "fa" ? "rtl" : "ltr"}
          >
            <div className="flex flex-col items-start gap-3">
              <div>
                <p className="font-medium">
                  <bdi>{inventory?.host.hostname || t("currentServer")}</bdi>
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {t("localServerScope")}
                </p>
              </div>
              <p className="text-xs text-muted-foreground">
                <bdi>{inventory?.host.os}</bdi>
              </p>
              <div className="flex w-full flex-col items-start gap-1">
                {addresses.map((ip) => (
                  <Address key={ip}>{ip}</Address>
                ))}
              </div>
              <AccessStatus />
            </div>
          </PopoverContent>
        </Popover>
        <ToggleGroup
          type="single"
          variant="outline"
          size="sm"
          aria-label={t("mode")}
          value={preferences.mode}
          onValueChange={(mode) =>
            mode &&
            setPreferences({
              ...preferences,
              mode: mode as Preferences["mode"],
            })
          }
        >
          {[
            { id: "light", icon: Sun },
            { id: "dark", icon: Moon },
            { id: "system", icon: Monitor },
          ].map(({ id, icon: Icon }) => (
            <ToggleGroupItem
              key={id}
              value={id}
              aria-label={t(id)}
              title={t(id)}
            >
              <Icon />
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
        <ActionButton
          variant="ghost"
          size="icon"
          label={t("refresh")}
          disabled={busy}
          onClick={refresh}
        >
          <RefreshCw />
        </ActionButton>
        <Button
          variant="ghost"
          size="sm"
          aria-label={t("language")}
          onClick={() =>
            setPreferences({
              ...preferences,
              locale: locale === "fa" ? "en" : "fa",
            })
          }
        >
          <Globe2 data-icon="inline-start" />
          <span className="hidden sm:inline">
            {locale === "fa" ? "EN" : "فا"}
          </span>
        </Button>
      </div>
    </header>
  );
}
