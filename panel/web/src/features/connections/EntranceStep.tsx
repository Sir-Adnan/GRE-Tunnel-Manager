// Step 1: what arrives here — engine, incoming ports (ranges stay one kernel
// rule), protocol and how several ports map to the remote side.
import { useContext } from "react";
import { ArrowRight, Equal, Repeat, Waypoints } from "lucide-react";
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldContent,
} from "@/components/ui/field";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Switch } from "@/components/ui/switch";
import { TextField, Choice } from "@/components/shared";
import { HelpTip } from "@/components/help";
import { LocaleContext, useT } from "@/lib/i18n";
import { engineName, number } from "@/lib/format";
import type { Inventory } from "@/lib/api";
import {
  mappingSamples,
  parseSpans,
  remoteSpans,
  totalPorts,
  type PortMode,
} from "@/lib/ports";
import { ProfilePicker } from "./ProfilePicker";
import type { ConnectionDraft } from "./useConnectionDraft";

const modes: {
  id: PortMode;
  icon: typeof Equal;
  title: string;
  help: string;
}[] = [
  { id: "same", icon: Equal, title: "portModeSame", help: "portModeSameHelp" },
  { id: "", icon: Waypoints, title: "portModeOne", help: "portModeOneHelp" },
  { id: "map", icon: Repeat, title: "portModeMap", help: "portModeMapHelp" },
];

export function EntranceStep({
  draft,
  inventory,
  engines,
  editing,
}: {
  draft: ConnectionDraft;
  inventory: Inventory;
  engines?: string[];
  editing: boolean;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const { value, patch, capability } = draft;
  const kernel = value.engine === "nftables" || value.engine === "iptables";
  const parsed = parseSpans(value.ports, kernel);
  const several =
    parsed.spans.length > 1 || parsed.spans.some((s) => s.last > s.first);
  const mode = value.port_mode || "";
  const remote = remoteSpans(
    parsed.spans,
    mode,
    value.remote_ports || "",
    value.targets[0]?.port || 443,
  );
  const portsError =
    value.ports && parsed.error ? t(`portsError_${parsed.error}`) : "";
  const total = totalPorts(parsed.spans);
  return (
    <FieldGroup>
      {!editing && (!engines || engines.length > 1) && (
        <Choice
          id="engine"
          label={t("method")}
          value={value.engine}
          choices={inventory.capabilities
            .filter((cap) => !engines || engines.includes(cap.id))
            .map((cap) => ({ value: cap.id, label: engineName(cap.id) }))}
          onChange={draft.changeEngine}
        />
      )}
      <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
        <TextField
          id="ports"
          label={t("localPorts")}
          help={t(kernel ? "portsHelpKernel" : "portsHelp")}
          placeholder={kernel ? "443, 8443, 2000-2999" : "443, 8443, 8000-8003"}
          dir="ltr"
          value={value.ports}
          onChange={(event) => {
            event.target.setCustomValidity("");
            patch("ports", event.target.value);
          }}
          onBlur={(event) => event.target.setCustomValidity(portsError)}
          required
          autoFocus
          maxLength={1024}
          aria-invalid={portsError ? true : undefined}
        />
        <Field>
          <FieldLabel className="min-h-8">{t("protocol")}</FieldLabel>
          <ToggleGroup
            type="single"
            variant="outline"
            value={value.protocol}
            aria-label={t("protocol")}
            onValueChange={(next) => next && patch("protocol", next)}
          >
            {capability.protocols.map((protocol) => (
              <ToggleGroupItem
                key={protocol}
                value={protocol}
                aria-label={t(protocol)}
              >
                {t(protocol)}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
        </Field>
      </div>
      <p
        className={
          portsError
            ? "text-xs text-destructive"
            : "text-xs text-muted-foreground"
        }
        role={portsError ? "alert" : undefined}
      >
        {portsError ||
          (total > 0
            ? t(kernel ? "portsSummaryKernel" : "portsSummary")
                .replace("{n}", number(total, locale))
                .replace(
                  "{r}",
                  number(kernel ? parsed.spans.length : total, locale),
                )
            : t("localServerScope"))}
      </p>
      {several && (
        <fieldset className="flex flex-col gap-3">
          <legend className="mb-2 flex items-center gap-1 text-sm font-medium">
            {t("portMapping")}
            <HelpTip>{t("portMappingHelp")}</HelpTip>
          </legend>
          <div
            className="choice-cards"
            role="radiogroup"
            aria-label={t("portMapping")}
          >
            {modes
              .filter((m) => m.id !== "map" || value.engine !== "iptables")
              .map(({ id, icon: Icon, title, help }) => (
                <label
                  key={id || "one"}
                  className="choice-card"
                  data-checked={mode === id || undefined}
                >
                  <input
                    type="radio"
                    name="port-mode"
                    className="sr-only"
                    checked={mode === id}
                    onChange={() => patch("port_mode", id)}
                  />
                  <Icon className="choice-card-icon" aria-hidden />
                  <span className="text-sm font-medium">{t(title)}</span>
                  <span className="text-xs text-muted-foreground">
                    {t(help)}
                  </span>
                </label>
              ))}
          </div>
          {value.engine === "iptables" && (
            <p className="text-xs text-muted-foreground">
              {t("portModeMapNft")}
            </p>
          )}
          {mode === "map" && (
            <TextField
              id="remote-ports"
              label={t("remotePorts")}
              help={t("remotePortsHelp")}
              placeholder="3000-3999, 443"
              dir="ltr"
              value={value.remote_ports || ""}
              onChange={(event) => {
                event.target.setCustomValidity("");
                patch("remote_ports", event.target.value);
              }}
              onBlur={(event) =>
                event.target.setCustomValidity(
                  remote.error ? t(`portsError_${remote.error}`) : "",
                )
              }
              required
              maxLength={1024}
            />
          )}
          {!parsed.error && !remote.error && parsed.spans.length > 0 && (
            <ul
              className="mapping-preview"
              dir="ltr"
              aria-label={t("portMappingPreview")}
            >
              {mappingSamples(parsed.spans, remote.spans).map((pair, i) => (
                <li key={i}>
                  <span>{pair.from}</span>
                  <ArrowRight aria-hidden className="size-3" />
                  <span>
                    {mode === ""
                      ? `${pair.to} (${t("portModeOneShort")})`
                      : pair.to}
                  </span>
                </li>
              ))}
              {parsed.spans.length > 4 && <li>… +{parsed.spans.length - 4}</li>}
            </ul>
          )}
          {mode === "map" && remote.error && value.remote_ports && (
            <p className="text-xs text-destructive" role="alert">
              {t(`portsError_${remote.error}`)}
            </p>
          )}
        </fieldset>
      )}
      <FieldGroup columns>
        <TextField
          id="connection-name"
          label={`${t("name")} · ${t("optional")}`}
          placeholder={`${value.engine}-${value.ports.split(/[-,\s]/)[0] || "443"}`}
          help={t("autoName")}
          value={value.name}
          onChange={(event) => patch("name", event.target.value)}
          maxLength={40}
        />
        <ProfilePicker
          presets={(inventory.presets || []).filter(
            (p) => p.engine === value.engine,
          )}
          value={draft.preset}
          onChange={draft.applyPreset}
          onReset={draft.resetDefaults}
          targetCount={value.targets.length}
        />
      </FieldGroup>
      <Field orientation="horizontal" className="items-center">
        <FieldContent>
          <div className="flex items-center gap-1">
            <FieldLabel htmlFor="connection-enabled">
              {t("startAfterSave")}
            </FieldLabel>
            <HelpTip>{t("startAfterSaveHelp")}</HelpTip>
          </div>
        </FieldContent>
        <Switch
          id="connection-enabled"
          checked={value.enabled}
          onCheckedChange={(next) => patch("enabled", next)}
        />
      </Field>
    </FieldGroup>
  );
}
