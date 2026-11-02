import { Check } from "lucide-react";
import { styleChoices } from "@/experience/style-choices";
import type { Swatches } from "@/experience/types";
import { useT } from "@/lib/i18n";
import { defaultPreferences } from "@/lib/preferences";
import type { Locale } from "@/lib/preferences";
import { cn } from "@/lib/utils";

/** Miniature of the panel in one mode, painted from registry swatches only (no stylesheet needed). */
function Miniature({ colors }: { colors?: Swatches["light"] }) {
  if (!colors) return null;
  return (
    <span
      className="theme-miniature"
      style={{ background: colors.background, borderColor: colors.border }}
      aria-hidden
    >
      <span
        className="theme-miniature-rail"
        style={{ background: colors.card, borderColor: colors.border }}
      >
        <i style={{ background: colors.primary }} />
        <i style={{ background: colors.muted }} />
        <i style={{ background: colors.muted }} />
      </span>
      <span className="theme-miniature-body">
        <b style={{ background: colors.foreground }} />
        <span
          className="theme-miniature-card"
          style={{ background: colors.card, borderColor: colors.border }}
        >
          <i style={{ background: colors.primary }} />
          <i style={{ background: colors.secondary }} />
        </span>
      </span>
    </span>
  );
}

export function ThemePicker({
  value,
  locale,
  onChange,
}: {
  value: string;
  locale: Locale;
  onChange: (style: string) => void;
}) {
  const t = useT();
  const items = styleChoices(locale, value);
  return (
    <div role="group" aria-label={t("style")} className="theme-grid">
      {items.map((item) => {
        const selected = item.id === value;
        return (
          <button
            key={item.id}
            type="button"
            aria-pressed={selected}
            onClick={() => onChange(item.id)}
            className={cn("theme-option", selected && "is-selected")}
          >
            <span className="theme-preview">
              <Miniature colors={item.swatches?.dark} />
              <Miniature colors={item.swatches?.light} />
            </span>
            <span className="flex min-w-0 items-center gap-2">
              <span className="truncate font-medium">{item.name}</span>
              {item.id === defaultPreferences.style && (
                <span className="theme-default">{t("defaultTheme")}</span>
              )}
              {selected && (
                <Check className="ms-auto size-4 shrink-0 text-primary-text" />
              )}
            </span>
            {item.description && (
              <span className="line-clamp-2 text-start text-xs leading-5 text-muted-foreground">
                {item.description}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
