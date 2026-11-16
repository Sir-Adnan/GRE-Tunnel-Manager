import {
  useContext,
  useState,
  type ComponentProps,
  type ReactNode,
} from "react";
import { MoreHorizontal } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useIsMobile } from "@/hooks/use-mobile";
import { LocaleContext, useT } from "@/lib/i18n";

export type MenuAction = {
  id: string;
  label: string;
  icon: ReactNode;
  onSelect: () => void;
  destructive?: boolean;
};

/**
 * A "more actions" button: a dropdown beside the pointer on larger screens and
 * a bottom sheet with full-width, thumb-sized rows on phones. One list of
 * groups feeds both, so every action exists in both places. `open` and
 * `onOpenChange` are optional; a card swipe uses them to open the same menu.
 */
export function ActionMenu({
  label,
  title,
  groups,
  disabled,
  open,
  onOpenChange,
}: {
  /** The trigger's accessible name, for example "More actions for Reality DE". */
  label: string;
  /** The sheet heading on phones (usually the item's name). */
  title: string;
  groups: MenuAction[][];
  disabled?: boolean;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const mobile = useIsMobile();
  const [own, setOwn] = useState(false);
  const isOpen = open ?? own;
  const setOpen = onOpenChange ?? setOwn;
  const visible = groups.filter((group) => group.length > 0);
  const trigger = (extra?: ComponentProps<typeof Button>) => (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      disabled={disabled}
      aria-label={label}
      {...extra}
    >
      <MoreHorizontal />
    </Button>
  );
  if (!mobile)
    return (
      <DropdownMenu
        open={isOpen}
        onOpenChange={setOpen}
        dir={locale === "fa" ? "rtl" : "ltr"}
      >
        <DropdownMenuTrigger asChild>{trigger()}</DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="min-w-52">
          {visible.map((group, index) => (
            <DropdownMenuGroup key={group[0].id}>
              {index > 0 && <DropdownMenuSeparator />}
              {group.map((action) => (
                <DropdownMenuItem
                  key={action.id}
                  variant={action.destructive ? "destructive" : "default"}
                  onSelect={action.onSelect}
                >
                  {action.icon}
                  {action.label}
                </DropdownMenuItem>
              ))}
            </DropdownMenuGroup>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
    );
  return (
    <Dialog open={isOpen} onOpenChange={setOpen}>
      {trigger({
        onClick: () => setOpen(true),
        "aria-haspopup": "dialog",
        "aria-expanded": isOpen,
      })}
      <DialogContent
        closeLabel={t("close")}
        showCloseButton={false}
        className="action-sheet"
      >
        <DialogHeader>
          <DialogTitle className="bidi-name truncate">{title}</DialogTitle>
          <DialogDescription className="sr-only">{label}</DialogDescription>
        </DialogHeader>
        {visible.map((group) => (
          <div key={group[0].id} role="group" className="action-sheet-group">
            {group.map((action) => (
              <button
                key={action.id}
                type="button"
                className="action-sheet-item"
                data-variant={action.destructive ? "destructive" : undefined}
                onClick={() => {
                  setOpen(false);
                  action.onSelect();
                }}
              >
                {action.icon}
                <span className="min-w-0 flex-1 truncate">{action.label}</span>
              </button>
            ))}
          </div>
        ))}
        <Button variant="outline" onClick={() => setOpen(false)}>
          {t("cancel")}
        </Button>
      </DialogContent>
    </Dialog>
  );
}
