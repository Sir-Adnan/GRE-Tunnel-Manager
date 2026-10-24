import { useContext, useState } from "react";
import { FieldGroup } from "@/components/ui/field";
import { TextField, Choice } from "@/components/shared";
import { LocaleContext, useT } from "@/lib/i18n";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { HealthCheckFields } from "./HealthCheckFields";
import { AffinityFields } from "./AffinityFields";
import { RoutingFields } from "./RoutingFields";
import { EngineOptionFields } from "./EngineOptionFields";
import type { ConnectionDraft } from "./useConnectionDraft";
export function ConnectionAdvanced({ draft }: { draft: ConnectionDraft }) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const [advancedTab, setAdvancedTab] = useState("limits");
  const { value, patch, capability } = draft;
  return (
    <Tabs
      dir={locale === "fa" ? "rtl" : "ltr"}
      value={capability.options.length ? advancedTab : "network"}
      onValueChange={setAdvancedTab}
      className="gap-4"
    >
      <TabsList className="w-full h-auto flex-wrap" aria-label={t("advanced")}>
        {capability.options.length > 0 && (
          <TabsTrigger data-advanced-tab="limits" value="limits">
            {t("limitsAndTimeouts")}
          </TabsTrigger>
        )}
        <TabsTrigger data-advanced-tab="network" value="network">
          {t("networkOptions")}
        </TabsTrigger>
        {value.engine === "haproxy" && (
          <TabsTrigger data-advanced-tab="routing" value="routing">
            {t("routingAndAffinity")}
          </TabsTrigger>
        )}
      </TabsList>
      {value.engine === "haproxy" && (
        <TabsContent
          forceMount
          className="data-[state=inactive]:hidden"
          data-advanced-section="routing"
          value="routing"
        >
          <FieldGroup>
            {value.engine === "haproxy" && (
              <RoutingFields
                value={value}
                onChange={(next) => patch("routing", next)}
              />
            )}

            {value.engine === "haproxy" && (
              <AffinityFields
                options={value.options}
                onChange={(next) => patch("options", next)}
              />
            )}

            <HealthCheckFields
              options={value.options}
              onChange={(next) => patch("options", next)}
            />
          </FieldGroup>
        </TabsContent>
      )}
      <TabsContent
        forceMount
        className="data-[state=inactive]:hidden"
        data-advanced-section="network"
        value="network"
      >
        <FieldGroup columns>
          <TextField
            id="bind"
            label={t("bind")}
            help={t("bindHelp")}
            dir="ltr"
            value={value.bind}
            onChange={(event) => patch("bind", event.target.value)}
            required
          />
          {["nftables", "iptables"].includes(value.engine) && (
            <>
              <TextField
                id="interface"
                label={t("interface")}
                value={value.interface}
                onChange={(event) => patch("interface", event.target.value)}
                dir="ltr"
                required
                maxLength={15}
              />
              <Choice
                id="snat"
                label={t("sourcePolicy")}
                value={value.snat}
                choices={["masquerade", "preserve"].map((id) => ({
                  value: id,
                  label: t(id),
                }))}
                onChange={(next) => patch("snat", next)}
              />
            </>
          )}
          <EngineOptionFields
            capability={capability}
            options={value.options}
            section="network"
            onChange={(next) => patch("options", next)}
          />
        </FieldGroup>
      </TabsContent>
      <TabsContent
        forceMount
        className="data-[state=inactive]:hidden"
        data-advanced-section="limits"
        value="limits"
      >
        <FieldGroup columns>
          <EngineOptionFields
            capability={capability}
            options={value.options}
            section="limits"
            onChange={(next) => patch("options", next)}
          />
        </FieldGroup>
      </TabsContent>
    </Tabs>
  );
}
