import { Check, Moon, Sun, Monitor } from "lucide-react";
import {
  Popover,
  PopoverTrigger,
  PopoverContent,
} from "@/components/ui/popover";
import { Button } from "@/components/ui/button";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { styleChoices } from "@/experience/style-choices";
import { useT } from "@/lib/i18n";
import type { Preferences } from "@/lib/preferences";

/** Quick appearance switcher: color mode plus the visual preset, without leaving the page. */
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
  const styles = styleChoices(preferences.locale, preferences.style);
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="icon" aria-label={t("appearance")}>
          <Icon />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        align="end"
        className="w-72 max-w-[calc(100vw-2rem)]"
        dir={preferences.locale === "fa" ? "rtl" : "ltr"}
      >
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <p className="text-xs font-medium text-muted-foreground">
              {t("mode")}
            </p>
            <ToggleGroup
              type="single"
              variant="outline"
              size="sm"
              aria-label={t("mode")}
              value={preferences.mode}
              className="w-full"
              onValueChange={(mode) =>
                mode &&
                onChange({ ...preferences, mode: mode as Preferences["mode"] })
              }
            >
              {[
                { id: "light", icon: Sun },
                { id: "dark", icon: Moon },
                { id: "system", icon: Monitor },
              ].map(({ id, icon: Glyph }) => (
                <ToggleGroupItem
                  key={id}
                  value={id}
                  aria-label={t(id)}
                  className="flex-1"
                >
                  <Glyph />
                  {t(id)}
                </ToggleGroupItem>
              ))}
            </ToggleGroup>
          </div>
          <div className="flex flex-col gap-1">
            <p className="mb-1 text-xs font-medium text-muted-foreground">
              {t("style")}
            </p>
            {styles.map((style) => {
              const colors = style.swatches?.dark;
              const selected = style.id === preferences.style;
              return (
                <button
                  key={style.id}
                  type="button"
                  aria-pressed={selected}
                  className="style-row"
                  onClick={() => onChange({ ...preferences, style: style.id })}
                >
                  <span className="style-swatch" aria-hidden>
                    <i style={{ background: colors?.background }} />
                    <i style={{ background: colors?.primary }} />
                    <i style={{ background: style.swatches?.light?.primary }} />
                  </span>
                  <span className="min-w-0 flex-1 truncate text-start">
                    {style.name}
                  </span>
                  {selected && <Check className="size-4 text-primary-text" />}
                </button>
              );
            })}
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}
