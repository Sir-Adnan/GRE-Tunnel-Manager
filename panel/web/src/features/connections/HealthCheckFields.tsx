import { FieldGroup, FieldSet, FieldLegend } from "@/components/ui/field";
import { Choice, TextField } from "@/components/shared";
import { HelpTip } from "@/components/help";
import { useT } from "@/lib/i18n";

export function HealthCheckFields({
  options,
  onChange,
  requireChecks = false,
}: {
  options: Record<string, string>;
  onChange: (value: Record<string, string>) => void;
  requireChecks?: boolean;
}) {
  const t = useT();
  const http = options.check_mode === "http";
  const set = (key: string, value: string) => {
    const next = { ...options };
    if (value === "") delete next[key];
    else next[key] = value;
    onChange(next);
  };
  return (
    <FieldSet>
      <FieldLegend className="inline-flex items-center gap-1">
        {t("healthProbe")}
        <HelpTip>{t("healthProbeHelp")}</HelpTip>
      </FieldLegend>
      <FieldGroup columns>
        <Choice
          id="option-check_mode"
          label={t("check_mode")}
          value={options.check_mode ?? "tcp"}
          choices={[
            { value: "off", label: t("off"), disabled: requireChecks },
            { value: "tcp", label: t("tcpConnect") },
            { value: "http", label: t("httpReadiness") },
          ]}
          onChange={(value) =>
            onChange({
              ...options,
              check_mode: value,
              ...(value === "http" &&
              (!options.check_port || options.check_port === "0")
                ? { check_port: "8080" }
                : {}),
            })
          }
        />
        {options.check_mode !== "off" && (
          <TextField
            id="option-check_port"
            label={t(http ? "readinessPort" : "check_port")}
            type="number"
            dir="ltr"
            min={http ? 1 : 0}
            max={65535}
            value={options.check_port ?? ""}
            placeholder="0"
            required={http}
            onChange={(event) => set("check_port", event.target.value)}
          />
        )}
        {http && (
          <>
            <TextField
              id="option-check_path"
              label={t("check_path")}
              dir="ltr"
              value={options.check_path ?? ""}
              placeholder="/health"
              maxLength={128}
              onChange={(event) => set("check_path", event.target.value)}
            />
            <TextField
              id="option-check_host"
              label={t("check_host")}
              dir="ltr"
              value={options.check_host ?? ""}
              placeholder="localhost"
              maxLength={253}
              onChange={(event) => set("check_host", event.target.value)}
            />
            <TextField
              id="option-check_status"
              label={t("check_status")}
              dir="ltr"
              type="number"
              min={200}
              max={599}
              value={options.check_status ?? ""}
              placeholder="200"
              onChange={(event) => set("check_status", event.target.value)}
            />
          </>
        )}
      </FieldGroup>
    </FieldSet>
  );
}
