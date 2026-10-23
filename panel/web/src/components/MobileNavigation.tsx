import { Gauge, Layers3, Activity, Server, Menu } from "lucide-react";
import { useSidebar } from "@/components/ui/sidebar";
import { useT } from "@/lib/i18n";
export function MobileNavigation({
  page,
  navigate,
}: {
  page: string;
  navigate: (p: string) => void;
}) {
  const t = useT(),
    { setOpenMobile, openMobile } = useSidebar();
  const links = [
    { id: "overview", icon: Gauge },
    { id: "connections", icon: Layers3 },
    { id: "traffic", icon: Activity },
    { id: "nodes", icon: Server },
  ];
  return (
    <nav
      aria-label={t("mobileNavigation")}
      className="fixed inset-x-3 bottom-[max(0.75rem,env(safe-area-inset-bottom))] z-30 grid grid-cols-5 rounded-2xl border bg-background/95 p-1.5 shadow-lg backdrop-blur-md md:hidden"
    >
      {links.map((item) => (
        <button
          key={item.id}
          type="button"
          aria-current={page === item.id ? "page" : undefined}
          className={`flex min-h-12 min-w-0 flex-col items-center justify-center gap-1 rounded-xl px-1 text-[10px] transition-colors ${page === item.id ? "bg-muted font-medium text-foreground" : "text-muted-foreground hover:bg-muted hover:text-foreground"}`}
          onClick={() => navigate(item.id)}
        >
          <item.icon className="size-4" />
          <span className="max-w-full truncate">{t(item.id)}</span>
        </button>
      ))}
      <button
        type="button"
        aria-expanded={openMobile}
        onClick={() => setOpenMobile(true)}
        className="flex min-h-12 flex-col items-center justify-center gap-1 rounded-xl px-1 text-[10px] text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
      >
        <Menu className="size-4" />
        <span>{t("moreNavigation")}</span>
      </button>
    </nav>
  );
}
