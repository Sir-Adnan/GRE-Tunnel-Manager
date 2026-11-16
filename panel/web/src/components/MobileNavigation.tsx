import { useEffect, useRef, useState } from "react";
import { Globe2, Menu, Plus, RefreshCw, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { mobileItems, navGroups, type NavItem } from "@/components/nav-items";
import { attentionItems } from "@/lib/attention";
import { barHidden } from "@/lib/gesture";
import { useT } from "@/lib/i18n";
import type { Inventory } from "@/lib/api";
import { cn } from "@/lib/utils";

/** Hides the bar while the page is read downward; see barHidden in lib/gesture. */
function useHiddenOnScroll() {
  const [hidden, setHidden] = useState(false);
  const state = useRef({ last: 0, hidden: false });
  useEffect(() => {
    let frame = 0;
    state.current.last = window.scrollY;
    const check = () => {
      frame = 0;
      const y = window.scrollY,
        s = state.current,
        dy = y - s.last;
      const atEnd =
        y + window.innerHeight >= document.documentElement.scrollHeight - 8;
      const next = barHidden(s.hidden, { y, dy, atEnd });
      // Small moves add up until they clearly go one way.
      if (Math.abs(dy) > 6 || y < 64) s.last = y;
      if (next !== s.hidden) setHidden((s.hidden = next));
    };
    const scrolled = () => {
      if (!frame) frame = requestAnimationFrame(check);
    };
    window.addEventListener("scroll", scrolled, { passive: true });
    return () => {
      window.removeEventListener("scroll", scrolled);
      cancelAnimationFrame(frame);
    };
  }, []);
  return hidden;
}

/**
 * The phone's bottom bar: four main pages and "More", a sheet with every other
 * page and the quick actions. A dot marks pages with something to look at.
 */
export function MobileNavigation({
  page,
  navigate,
  inventory,
  add,
  openPalette,
  switchLocale,
  refresh,
}: {
  page: string;
  navigate: (p: string) => void;
  inventory?: Inventory;
  add: () => void;
  openPalette: () => void;
  /** The top bar hides these on narrow phones; the sheet keeps them reachable. */
  switchLocale: () => void;
  refresh: () => void;
}) {
  const t = useT();
  const [more, setMore] = useState(false);
  const [focused, setFocused] = useState(false);
  const scrolledAway = useHiddenOnScroll();
  const issues = inventory ? attentionItems(inventory) : [];
  const alert = (id: string) =>
    id === "overview"
      ? issues.length > 0
      : id === "connections" &&
        issues.some((item) => item.kind === "connection");
  const rest = navGroups
    .map((group) => ({
      title: group.title,
      items: group.items.filter((item) => !mobileItems.includes(item)),
    }))
    .filter((group) => group.items.length > 0);
  const inMore = rest.some((group) =>
    group.items.some((item) => item.id === page),
  );
  const go = (item: NavItem) => {
    setMore(false);
    navigate(item.id);
  };
  return (
    <>
      <nav
        aria-label={t("mobileNavigation")}
        className="mobile-nav md:hidden"
        data-hidden={scrolledAway && !focused && !more ? "" : undefined}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
      >
        {mobileItems.map((item) => (
          <button
            key={item.id}
            type="button"
            aria-current={page === item.id ? "page" : undefined}
            className={cn("mobile-nav-item", page === item.id && "is-active")}
            onClick={() => navigate(item.id)}
          >
            <span className="mobile-nav-icon">
              <item.icon className="size-[18px]" />
              {alert(item.id) && <span className="mobile-nav-dot" />}
            </span>
            <span className="max-w-full truncate">{t(item.id)}</span>
            {alert(item.id) && (
              <span className="sr-only">{t("needsAttention")}</span>
            )}
          </button>
        ))}
        <button
          type="button"
          aria-haspopup="dialog"
          aria-expanded={more}
          onClick={() => setMore(true)}
          className={cn("mobile-nav-item", inMore && "is-active")}
        >
          <Menu className="size-[18px]" />
          <span>{t("moreNavigation")}</span>
        </button>
      </nav>
      <Dialog open={more} onOpenChange={setMore}>
        <DialogContent closeLabel={t("close")} className="more-sheet">
          <DialogHeader>
            <DialogTitle>{t("morePages")}</DialogTitle>
            <DialogDescription className="sr-only">
              {t("mobileNavigation")}
            </DialogDescription>
          </DialogHeader>
          <div
            className="more-quick"
            role="group"
            aria-label={t("quickActions")}
          >
            <Button
              variant="outline"
              onClick={() => {
                setMore(false);
                add();
              }}
            >
              <Plus data-icon="inline-start" />
              <span className="truncate">{t("newConnection")}</span>
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                setMore(false);
                openPalette();
              }}
            >
              <Search data-icon="inline-start" />
              <span className="truncate">{t("commandPalette")}</span>
            </Button>
            <Button
              variant="outline"
              className="sm:hidden"
              onClick={switchLocale}
            >
              <Globe2 data-icon="inline-start" />
              <span className="truncate">{t("otherLanguage")}</span>
            </Button>
            <Button
              variant="outline"
              className="sm:hidden"
              onClick={() => {
                setMore(false);
                refresh();
              }}
            >
              <RefreshCw data-icon="inline-start" />
              <span className="truncate">{t("refresh")}</span>
            </Button>
          </div>
          {rest.map((group) => (
            <section key={group.title} className="more-section">
              <h3>{t(group.title)}</h3>
              <div className="more-grid">
                {group.items.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    className="more-tile"
                    aria-current={page === item.id ? "page" : undefined}
                    onClick={() => go(item)}
                  >
                    <item.icon aria-hidden />
                    <span className="max-w-full truncate">{t(item.id)}</span>
                  </button>
                ))}
              </div>
            </section>
          ))}
        </DialogContent>
      </Dialog>
    </>
  );
}
