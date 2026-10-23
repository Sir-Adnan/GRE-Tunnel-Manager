import { Plus, Trash2 } from "lucide-react";
import { FieldSet, FieldLegend, FieldGroup } from "@/components/ui/field";
import { Button } from "@/components/ui/button";
import { Choice, TextField } from "@/components/shared";
import { HelpTip } from "@/components/help";
import { ActionButton } from "@/components/help";
import { useT } from "@/lib/i18n";
import type { Connection, Routing } from "@/lib/api";
export function RoutingFields({
  value,
  onChange,
}: {
  value: Connection;
  onChange: (r: Routing | undefined) => void;
}) {
  const t = useT(),
    r = value.routing;
  return (
    <FieldSet className="rounded-xl border p-4">
      <FieldLegend className="inline-flex items-center gap-1">
        {t("applicationRouting")}
        <HelpTip>{t("routingHelp")}</HelpTip>
      </FieldLegend>
      <FieldGroup>
        <Choice
          id="routing-mode"
          label={t("routingMode")}
          value={r?.mode || "tcp"}
          onChange={(v) =>
            onChange(
              v === "tcp"
                ? undefined
                : {
                    version: 1,
                    mode: v as Routing["mode"],
                    certificate: v === "https" ? r?.certificate || "" : "",
                    rules: (r?.rules || []).map((rule) => ({
                      ...rule,
                      prefix: v === "sni" ? "" : rule.prefix,
                    })),
                  },
            )
          }
          choices={["tcp", "sni", "http", "https"].map((v) => ({
            value: v,
            label: t(`routeMode_${v}`),
          }))}
        />
        {r && (
          <>
            <div className="flex justify-end">
              <HelpTip>
                {t(r.mode === "sni" ? "sniHelp" : "httpRoutingHelp")}
              </HelpTip>
            </div>
            {r.mode === "https" && (
              <TextField
                id="routing-certificate"
                label={t("certificateID")}
                help={t("certificateHelp")}
                dir="ltr"
                value={r.certificate}
                required
                maxLength={40}
                pattern="[a-zA-Z0-9][a-zA-Z0-9_\-]{0,39}"
                onChange={(e) =>
                  onChange({ ...r, certificate: e.target.value })
                }
              />
            )}
            {r.rules.map((rule, index) => (
              <div
                key={index}
                className="flex flex-col gap-4 rounded-lg border p-3"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium">
                    {t("routeRule")} <bdi>{index + 1}</bdi>
                  </span>
                  <ActionButton
                    type="button"
                    variant="ghost"
                    size="icon"
                    label={t("delete")}
                    onClick={() =>
                      onChange({
                        ...r,
                        rules: r.rules.filter((_, i) => i !== index),
                      })
                    }
                  >
                    <Trash2 />
                  </ActionButton>
                </div>
                <TextField
                  id={`route-host-${index}`}
                  label={t("routeHost")}
                  dir="ltr"
                  required
                  value={rule.host}
                  maxLength={253}
                  onChange={(e) =>
                    onChange({
                      ...r,
                      rules: r.rules.map((v, i) =>
                        i === index
                          ? { ...v, host: e.target.value.toLowerCase() }
                          : v,
                      ),
                    })
                  }
                />
                {r.mode !== "sni" && (
                  <TextField
                    id={`route-path-${index}`}
                    label={t("routePrefix")}
                    dir="ltr"
                    value={rule.prefix}
                    maxLength={128}
                    onChange={(e) =>
                      onChange({
                        ...r,
                        rules: r.rules.map((v, i) =>
                          i === index ? { ...v, prefix: e.target.value } : v,
                        ),
                      })
                    }
                  />
                )}
                <Choice
                  id={`route-target-${index}`}
                  label={t("destination")}
                  value={String(rule.target)}
                  onChange={(v) =>
                    onChange({
                      ...r,
                      rules: r.rules.map((rule, i) =>
                        i === index ? { ...rule, target: Number(v) } : rule,
                      ),
                    })
                  }
                  choices={value.targets.map((target, i) => ({
                    value: String(i + 1),
                    label: `${i + 1} · ${target.ip || "…"}:${target.port}`,
                  }))}
                />
              </div>
            ))}
            {r.rules.length < 16 && (
              <Button
                type="button"
                variant="outline"
                onClick={() =>
                  onChange({
                    ...r,
                    rules: [...r.rules, { host: "", prefix: "", target: 1 }],
                  })
                }
              >
                <Plus data-icon="inline-start" />
                {t("addRoute")}
              </Button>
            )}
          </>
        )}
      </FieldGroup>
    </FieldSet>
  );
}
