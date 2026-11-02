import { useContext } from "react";
import { Network, Search } from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";
import { AccessStatus } from "@/components/AccessStatus";
import { Logo } from "@/components/shared";
import { navGroups } from "@/components/nav-items";
import { LocaleContext, useT } from "@/lib/i18n";
import { number } from "@/lib/format";
import { attentionItems } from "@/lib/attention";
import type { Inventory } from "@/lib/api";
import { panelVersion } from "@/lib/version";

/** Uses the official shadcn sidebar composition, with one navigation for all viewports. */
export function PanelSidebar({
  page,
  inventory,
  navigate,
  openPalette,
}: {
  page: string;
  inventory?: Inventory;
  navigate: (page: string) => void;
  openPalette: () => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { setOpenMobile } = useSidebar();
  const issues = inventory ? attentionItems(inventory).length : 0;
  const badge = (id: string) =>
    !inventory
      ? undefined
      : id === "connections"
        ? number(inventory.connections.length, locale)
        : id === "overview" && issues
          ? number(issues, locale)
          : undefined;
  return (
    <Sidebar
      side={locale === "fa" ? "right" : "left"}
      collapsible="icon"
      mobileTitle={t("workspace")}
    >
      <SidebarHeader>
        <div className="flex min-h-14 items-center justify-between gap-2 px-2 group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:px-0">
          <span className="hidden group-data-[collapsible=icon]:block">
            <Network className="size-5 text-primary-text" />
          </span>
          <div className="group-data-[collapsible=icon]:hidden">
            <Logo />
          </div>
          <SidebarTrigger
            aria-label={t("toggleSidebar")}
            className="md:hidden"
          />
        </div>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              className="sidebar-search"
              tooltip={{
                children: t("commandPalette"),
                side: locale === "fa" ? "left" : "right",
              }}
              onClick={() => {
                setOpenMobile(false);
                openPalette();
              }}
            >
              <Search />
              <span className="min-w-0 flex-1 truncate">
                {t("commandPlaceholder")}
              </span>
              <kbd className="kbd group-data-[collapsible=icon]:hidden">
                Ctrl K
              </kbd>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <nav aria-label={t("workspace")}>
          {navGroups.map((group) => (
            <SidebarGroup key={group.title}>
              <SidebarGroupLabel>{t(group.title)}</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {group.items.map((item) => {
                    const count = badge(item.id);
                    return (
                      <SidebarMenuItem key={item.id}>
                        <SidebarMenuButton
                          isActive={page === item.id}
                          aria-current={page === item.id ? "page" : undefined}
                          tooltip={{
                            children: t(item.id),
                            side: locale === "fa" ? "left" : "right",
                          }}
                          onClick={() => {
                            navigate(item.id);
                            setOpenMobile(false);
                          }}
                        >
                          <item.icon />
                          <span className="min-w-0 flex-1 truncate">
                            {t(item.id)}
                          </span>
                        </SidebarMenuButton>
                        {count && (
                          <SidebarMenuBadge
                            className={
                              item.id === "overview" ? "is-alert" : undefined
                            }
                            aria-label={
                              item.id === "overview"
                                ? `${count} ${t("needsAttention")}`
                                : undefined
                            }
                          >
                            {count}
                          </SidebarMenuBadge>
                        )}
                      </SidebarMenuItem>
                    );
                  })}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          ))}
        </nav>
      </SidebarContent>
      <SidebarFooter>
        <div className="sidebar-server">
          <span className="live-dot" aria-hidden />
          <div className="min-w-0 flex-1 group-data-[collapsible=icon]:hidden">
            <p className="truncate text-xs font-medium">
              <bdi>{inventory?.host.hostname || t("currentServer")}</bdi>
            </p>
            <p className="text-xs text-muted-foreground">
              <bdi>v{inventory?.version || panelVersion}</bdi>
            </p>
          </div>
          <span className="group-data-[collapsible=icon]:hidden">
            <AccessStatus />
          </span>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
