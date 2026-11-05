import { useContext } from "react";
import { ChevronRight, Globe2, RefreshCw, Search, Server } from "lucide-react";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { AppearanceControl } from "@/components/AppearanceControl";
import { ActionButton } from "@/components/help";
import { Address } from "@/components/shared";
import { AccessStatus } from "@/components/AccessStatus";
import { NotificationCenter } from "@/features/notifications/NotificationCenter";
import { LocaleContext, useT } from "@/lib/i18n";
import type { Inventory } from "@/lib/api";
import type { Preferences } from "@/lib/preferences";

export function PanelHeader({
  page,
  inventory,
  preferences,
  setPreferences,
  busy,
  refresh,
  openPalette,
  navigate,
}: {
  page: string;
  inventory?: Inventory;
  preferences: Preferences;
  setPreferences: (value: Preferences) => void;
  busy: boolean;
  refresh: () => void;
  openPalette: () => void;
  navigate: (page: string, params?: Record<string, string>) => void;
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
        <span className="truncate text-sm font-medium">{t(page)}</span>
      </div>
      <div className="flex shrink-0 items-center gap-1 sm:gap-2">
        <ActionButton
          variant="ghost"
          size="icon"
          className="md:hidden"
          label={t("commandPalette")}
          onClick={openPalette}
        >
          <Search />
        </ActionButton>
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
        <NotificationCenter navigate={navigate} />
        <AppearanceControl
          preferences={preferences}
          onChange={setPreferences}
        />
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
