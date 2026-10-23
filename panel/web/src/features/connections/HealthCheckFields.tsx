import {
  FieldGroup,
  FieldSet,
  FieldLegend,
  FieldDescription,
} from "@/components/ui/field";
import { Choice, TextField } from "@/components/shared";
import { useT } from "@/lib/i18n";

export function HealthCheckFields({
  options,
  onChange,
}: {
  options: Record<string, string>;
  onChange: (value: Record<string, string>) => void;
}) {
  const t = useT();
  const http = options.check_mode === "http";
  const set = (key: string, value: string) =>
    onChange({ ...options, [key]: value });
  return (
    <FieldSet>
      <FieldLegend>{t("healthProbe")}</FieldLegend>
      <FieldDescription>{t("healthProbeHelp")}</FieldDescription>
      <FieldGroup>
        <Choice
          id="option-check_mode"
          label={t("check_mode")}
          value={options.check_mode ?? "tcp"}
          choices={[
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
        <TextField
          id="option-check_port"
          label={t(http ? "readinessPort" : "check_port")}
          type="number"
          dir="ltr"
          min={http ? 1 : 0}
          max={65535}
          value={options.check_port ?? "0"}
          required
          onChange={(event) => set("check_port", event.target.value)}
        />
        {http && (
          <>
            <TextField
              id="option-check_path"
              label={t("check_path")}
              dir="ltr"
              value={options.check_path ?? "/health"}
              maxLength={128}
              required
              onChange={(event) => set("check_path", event.target.value)}
            />
            <TextField
              id="option-check_host"
              label={t("check_host")}
              dir="ltr"
              value={options.check_host ?? "localhost"}
              maxLength={253}
              required
              onChange={(event) => set("check_host", event.target.value)}
            />
            <TextField
              id="option-check_status"
              label={t("check_status")}
              dir="ltr"
              type="number"
              min={200}
              max={599}
              value={options.check_status ?? "200"}
              required
              onChange={(event) => set("check_status", event.target.value)}
            />
          </>
        )}
      </FieldGroup>
    </FieldSet>
  );
}
