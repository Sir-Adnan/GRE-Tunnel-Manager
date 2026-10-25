import { FieldSet, FieldLegend, FieldGroup } from "@/components/ui/field";
import { Choice, TextField } from "@/components/shared";
import { HelpTip } from "@/components/help";
import { useT } from "@/lib/i18n";
export function AffinityFields({
  options,
  onChange,
}: {
  options: Record<string, string>;
  onChange: (o: Record<string, string>) => void;
}) {
  const t = useT(),
    enabled = options.stick === "source";
  const set = (key: string, value: string) => {
    const next = { ...options };
    if (value === "") delete next[key];
    else next[key] = value;
    onChange(next);
  };
  return (
    <FieldSet className="rounded-xl border p-4">
      <FieldLegend className="inline-flex items-center gap-1">
        {t("clientAffinity")}
        <HelpTip>{t("affinityHelp")}</HelpTip>
      </FieldLegend>
      <FieldGroup>
        <Choice
          id="option-stick"
          label={t("stick")}
          value={options.stick || "off"}
          choices={[
            { value: "off", label: t("off") },
            { value: "source", label: t("rememberSourceIP") },
          ]}
          onChange={(v) => set("stick", v)}
        />
        {enabled && (
          <FieldGroup columns>
            <TextField
              id="option-stick_size"
              label={t("stick_size")}
              type="number"
              min={1024}
              max={1000000}
              value={options.stick_size ?? ""}
              placeholder="16384"
              onChange={(e) => set("stick_size", e.target.value)}
            />
            <TextField
              id="option-stick_expire"
              label={t("stick_expire")}
              type="number"
              min={30}
              max={86400}
              value={options.stick_expire ?? ""}
              placeholder="1800"
              onChange={(e) => set("stick_expire", e.target.value)}
            />
          </FieldGroup>
        )}
      </FieldGroup>
    </FieldSet>
  );
}
