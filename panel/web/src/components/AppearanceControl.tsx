import { Moon, Sun, Monitor } from "lucide-react";
import {
  Popover,
  PopoverTrigger,
  PopoverContent,
} from "@/components/ui/popover";
import { Button } from "@/components/ui/button";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { useT } from "@/lib/i18n";
import type { Preferences } from "@/features/Settings";

export function AppearanceControl({
  preferences,
  onChange,
}: {
  preferences: Preferences;
  onChange: (p: Preferences) => void;
}) {
  const t = useT(),
    Icon =
      preferences.mode === "dark"
        ? Moon
        : preferences.mode === "light"
          ? Sun
          : Monitor;
  const controls = (
    <ToggleGroup
      type="single"
      variant="outline"
      size="sm"
      aria-label={t("mode")}
      value={preferences.mode}
      onValueChange={(mode) =>
        mode && onChange({ ...preferences, mode: mode as Preferences["mode"] })
      }
    >
      {[
        { id: "light", icon: Sun },
        { id: "dark", icon: Moon },
        { id: "system", icon: Monitor },
      ].map(({ id, icon: Glyph }) => (
        <ToggleGroupItem key={id} value={id} aria-label={t(id)} title={t(id)}>
          <Glyph />
          <span className="sm:sr-only">{t(id)}</span>
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  );
  return (
    <>
      <div className="hidden sm:block">{controls}</div>
      <div className="sm:hidden">
        <Popover>
          <PopoverTrigger asChild>
            <Button variant="ghost" size="icon" aria-label={t("mode")}>
              <Icon />
            </Button>
          </PopoverTrigger>
          <PopoverContent
            align="end"
            className="w-fit max-w-[calc(100vw-2rem)]"
          >
            <div className="flex flex-col gap-3">
              <p className="text-sm font-medium">{t("mode")}</p>
              {controls}
            </div>
          </PopoverContent>
        </Popover>
      </div>
    </>
  );
}
