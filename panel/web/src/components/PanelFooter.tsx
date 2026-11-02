import { Command } from "lucide-react";
import { useT } from "@/lib/i18n";
import type { Inventory } from "@/lib/api";
import { panelVersion } from "@/lib/version";

/** Quiet page footer: product and version, plus the keyboard entry point for power users. */
export function PanelFooter({ inventory }: { inventory?: Inventory }) {
  const t = useT();
  return (
    <footer className="app-footer">
      <span dir="ltr">
        Tunnel Manager <bdi>v{inventory?.version || panelVersion}</bdi>
      </span>
      <span className="hidden items-center gap-1.5 md:inline-flex">
        <Command className="size-3.5" />
        <kbd className="kbd">Ctrl K</kbd>
        {t("commandPalette")}
      </span>
    </footer>
  );
}
