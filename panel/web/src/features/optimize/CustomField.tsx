import type { CSSProperties } from "react";
import { RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  NativeSelect,
  NativeSelectOption,
} from "@/components/ui/native-select";
import { useT } from "@/lib/i18n";
import { compactValue, customValid } from "./catalog";
import type { OptimizeChange } from "./types";

const fieldNames: Record<string, string[]> = {
  triple: ["optFieldMin", "optFieldDefault", "optFieldMax"],
  range: ["optFieldLow", "optFieldHigh"],
  number: ["optFieldValue"],
};

/**
 * Edits one custom value within the bounds the server allows. Multi-field
 * values (buffer triples, the port range) get one input per field.
 */
export function CustomField({
  change,
  draft,
  onChange,
  onReset,
}: {
  change: OptimizeChange;
  draft: string;
  onChange: (value: string) => void;
  onReset: () => void;
}) {
  const t = useT();
  const id = `opt-custom-${change.key.replaceAll(".", "-")}`;
  const valid = customValid(change, draft);
  const hint = `${id}-hint`;
  const reset = (
    <Button type="button" variant="ghost" size="sm" onClick={onReset}>
      <RotateCcw data-icon="inline-start" />
      {t("optUseRecommended")}
    </Button>
  );
  if (change.kind === "choice")
    return (
      <div className="opt-custom">
        <label htmlFor={id} className="sr-only">
          {t("optFieldValue")}
        </label>
        <NativeSelect
          id={id}
          size="sm"
          value={draft}
          onChange={(e) => onChange(e.target.value)}
        >
          {(change.choices ?? []).map((c) => (
            <NativeSelectOption key={c} value={c}>
              {c}
            </NativeSelectOption>
          ))}
        </NativeSelect>
        {reset}
      </div>
    );
  const names = fieldNames[change.kind ?? "number"];
  const parts = draft.split(" ");
  while (parts.length < names.length) parts.push("");
  return (
    <div className="opt-custom">
      <div
        className="opt-custom-fields"
        dir="ltr"
        style={{ "--fields": names.length } as CSSProperties}
      >
        {names.map((name, i) => (
          <label key={name} className="opt-custom-field">
            <span>{t(name)}</span>
            <Input
              inputMode="numeric"
              autoComplete="off"
              aria-invalid={!valid}
              aria-describedby={hint}
              value={parts[i]}
              onChange={(e) => {
                const next = [...parts];
                next[i] = e.target.value.replace(/\D/g, "");
                onChange(next.slice(0, names.length).join(" "));
              }}
            />
          </label>
        ))}
      </div>
      <p id={hint} className="opt-why" data-invalid={!valid}>
        {t(
          change.kind === "number" ? "optAllowed" : `optAllowed_${change.kind}`,
        )
          .replace("{min}", compactValue(change.key, String(change.min)))
          .replace("{max}", compactValue(change.key, String(change.max)))}
      </p>
      {reset}
    </div>
  );
}
