import { useContext } from "react";
import { Choice } from "@/components/shared";
import { LocaleContext, useT } from "@/lib/i18n";
import type { Preset } from "@/lib/api";

export function ProfilePicker({
  presets,
  value,
  onChange,
  targetCount = 1,
}: {
  presets: Preset[];
  value: string;
  onChange: (p: Preset | undefined) => void;
  targetCount?: number;
}) {
  const t = useT(),
    locale = useContext(LocaleContext),
    selected = presets.find((p) => p.id === value);
  return (
    <div className="flex flex-col gap-2">
      <Choice
        id="preset"
        label={t("connectionProfile")}
        help={selected ? selected.help[locale] || selected.help.en : undefined}
        value={selected ? value : "custom"}
        onChange={(id) => onChange(presets.find((p) => p.id === id))}
        choices={[
          { value: "custom", label: t("customProfile") },
          ...presets.map((p) => ({
            value: p.id,
            label: p.label[locale] || p.label.en,
            disabled: !!p.max_targets && targetCount > p.max_targets,
          })),
        ]}
      />
    </div>
  );
}
