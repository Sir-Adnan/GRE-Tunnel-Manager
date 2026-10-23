import { useContext } from "react";
import {
  Activity,
  ArrowRight,
  Gauge,
  Layers3,
  Network,
  Server,
  Settings2,
  Workflow,
} from "lucide-react";
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
import { Separator } from "@/components/ui/separator";
import { AccessStatus } from "@/components/AccessStatus";
import { Logo } from "@/components/shared";
import { LocaleContext, useT } from "@/lib/i18n";
import { number } from "@/lib/format";
import type { Inventory } from "@/lib/api";

const groups = [
  {
    title: "workspace",
    items: [
      { id: "overview", icon: Gauge },
      { id: "connections", icon: Layers3 },
      { id: "traffic", icon: Activity },
    ],
  },
  {
    title: "infrastructure",
    items: [
      { id: "nodes", icon: Server },
      { id: "gre", icon: Network },
      { id: "forwarding", icon: ArrowRight },
      { id: "haproxy", icon: Workflow, label: "HAProxy" },
      { id: "realm", icon: Network, label: "Realm" },
      { id: "reverse", icon: ArrowRight },
    ],
  },
  {
    title: "preferences",
    items: [
      { id: "components", icon: Server },
      { id: "settings", icon: Settings2 },
    ],
  },
];

/** Uses the official shadcn sidebar composition, with one navigation for all viewports. */
export function PanelSidebar({
  page,
  inventory,
  navigate,
}: {
  page: string;
  inventory?: Inventory;
  navigate: (page: string) => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { setOpenMobile } = useSidebar();
  return (
    <Sidebar
      side={locale === "fa" ? "right" : "left"}
      collapsible="icon"
      mobileTitle={t("workspace")}
    >
      <SidebarHeader>
        <div className="flex min-h-16 items-center justify-between gap-2 px-2 group-data-[collapsible=icon]:px-0">
          <Network className="hidden size-5 group-data-[collapsible=icon]:block" />
          <div className="group-data-[collapsible=icon]:hidden">
            <Logo />
          </div>
          <SidebarTrigger
            aria-label={t("toggleSidebar")}
            className="md:hidden"
          />
        </div>
      </SidebarHeader>
      <SidebarContent>
        <nav aria-label={t("workspace")}>
          {groups.map((group) => (
            <SidebarGroup key={group.title}>
              <SidebarGroupLabel>{t(group.title)}</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {group.items.map((item) => (
                    <SidebarMenuItem key={item.id}>
                      <SidebarMenuButton
                        isActive={page === item.id}
                        aria-current={page === item.id ? "page" : undefined}
                        tooltip={{
                          children: "label" in item ? item.label : t(item.id),
                          side: locale === "fa" ? "left" : "right",
                        }}
                        onClick={() => {
                          navigate(item.id);
                          setOpenMobile(false);
                        }}
                      >
                        <item.icon
                          className={
                            item.icon === ArrowRight
                              ? "rtl:rotate-180"
                              : undefined
                          }
                        />
                        <span>{"label" in item ? item.label : t(item.id)}</span>
                      </SidebarMenuButton>
                      {item.id === "connections" && inventory && (
                        <SidebarMenuBadge>
                          {number(inventory.connections.length, locale)}
                        </SidebarMenuBadge>
                      )}
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          ))}
        </nav>
      </SidebarContent>
      <SidebarFooter>
        <Separator />
        <div className="flex items-center gap-3 px-2 py-3">
          <Server className="size-4 shrink-0" />
          <div className="min-w-0 flex-1 group-data-[collapsible=icon]:hidden">
            <p className="truncate text-xs font-medium">
              <bdi>{inventory?.host.hostname || "Server"}</bdi>
            </p>
            <p className="text-xs text-muted-foreground">
              <bdi>v{inventory?.version || "1.3.0"}</bdi>
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
