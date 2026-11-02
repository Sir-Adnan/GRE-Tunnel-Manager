import { Menu } from "lucide-react";
import { useSidebar } from "@/components/ui/sidebar";
import { mobileItems } from "@/components/nav-items";
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export function MobileNavigation({
  page,
  navigate,
}: {
  page: string;
  navigate: (p: string) => void;
}) {
  const t = useT(),
    { setOpenMobile, openMobile } = useSidebar();
  return (
    <nav aria-label={t("mobileNavigation")} className="mobile-nav md:hidden">
      {mobileItems.map((item) => (
        <button
          key={item.id}
          type="button"
          aria-current={page === item.id ? "page" : undefined}
          className={cn("mobile-nav-item", page === item.id && "is-active")}
          onClick={() => navigate(item.id)}
        >
          <item.icon className="size-[18px]" />
          <span className="max-w-full truncate">{t(item.id)}</span>
        </button>
      ))}
      <button
        type="button"
        aria-expanded={openMobile}
        onClick={() => setOpenMobile(true)}
        className="mobile-nav-item"
      >
        <Menu className="size-[18px]" />
        <span>{t("moreNavigation")}</span>
      </button>
    </nav>
  );
}
