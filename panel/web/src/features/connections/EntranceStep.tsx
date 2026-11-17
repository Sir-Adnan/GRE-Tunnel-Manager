// Step 1: what arrives here, as three short sections — the method (engine),
// the entrance (ports, protocol and how several ports map to the remote side;
// ranges stay one kernel rule) and the optional name, preset and start.
import { autoFocusField } from "@/lib/focus";
import { useContext } from "react";
import {
  ArrowRight,
  DoorOpen,
  Equal,
  Lock,
  Repeat,
  Route,
  Tag,
  Waypoints,
} from "lucide-react";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Switch } from "@/components/ui/switch";
import { TextField, Choice, EngineGlyph } from "@/components/shared";
import { ChoiceCards } from "@/components/ChoiceCards";
import { FormSection } from "@/components/FormSection";
import { HelpTip } from "@/components/help";
import { LocaleContext, useT } from "@/lib/i18n";
import { engineName, number } from "@/lib/format";
import type { Capability, Inventory } from "@/lib/api";
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

/** Engines with a one-line explanation; others fall back to a select. */
const described = ["nftables", "iptables", "haproxy", "realm"];

function MethodSection({
  draft,
  inventory,
  engines,
}: {
  draft: ConnectionDraft;
  inventory: Inventory;
  engines?: string[];
}) {
  const t = useT();
  const available = inventory.capabilities.filter(
    (cap: Capability) => !engines || engines.includes(cap.id),
  );
  const cards =
    available.length <= 4 &&
    available.every((cap) => described.includes(cap.id));
  return (
    <FormSection
      icon={<Route />}
      title={t("sectionMethod")}
      description={t("sectionMethodHelp")}
    >
      {cards ? (
        <ChoiceCards
          name="engine"
          label={t("method")}
          value={draft.value.engine}
          compact
          choices={available.map((cap) => ({
            id: cap.id,
            icon: <EngineGlyph engine={cap.id} />,
            title: engineName(cap.id),
            help: t(`engineBlurb_${cap.id}`),
            note:
              inventory.components.find((c) => c.id === cap.id)?.installed ===
              false
                ? t("notInstalled")
                : undefined,
          }))}
          onChange={draft.changeEngine}
        />
      ) : (
        <Choice
          id="engine"
          label={t("method")}
          labelHidden
          value={draft.value.engine}
          choices={available.map((cap) => ({
            value: cap.id,
            label: engineName(cap.id),
          }))}
          onChange={draft.changeEngine}
        />
      )}
    </FormSection>
  );
}

function ProtocolField({ draft }: { draft: ConnectionDraft }) {
  const t = useT();
  const { value, patch, capability } = draft;
  const only = capability.protocols.length === 1;
  return (
    <Field data-inline-error>
      <div className="field-label-row">
        <FieldLabel>{t("protocol")}</FieldLabel>
      </div>
      {only ? (
        <>
          <span className="field-static" aria-describedby="protocol-note">
            <Lock aria-hidden />
            {t(capability.protocols[0])}
          </span>
          <p id="protocol-note" className="field-hint">
            {t("protocolFixed")
              .replace("{engine}", engineName(value.engine))
              .replace("{p}", t(capability.protocols[0]))}
          </p>
        </>
      ) : (
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
      )}
    </Field>
  );
}

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
  const { value, patch } = draft;
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
  const remoteError =
    mode === "map" && remote.error && value.remote_ports
      ? t(`portsError_${remote.error}`)
      : "";
  return (
    <div className="form-sections">
      {!editing && (!engines || engines.length > 1) && (
        <MethodSection draft={draft} inventory={inventory} engines={engines} />
      )}
      <FormSection
        icon={<DoorOpen />}
        title={t("stepEntrance")}
        description={t("sectionEntranceHelp")}
      >
        <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
          <TextField
            id="ports"
            label={t("localPorts")}
            help={t(kernel ? "portsHelpKernel" : "portsHelp")}
            placeholder={
              kernel ? "443, 8443, 2000-2999" : "443, 8443, 8000-8003"
            }
            dir="ltr"
            value={value.ports}
            onChange={(event) => {
              event.target.setCustomValidity("");
              patch("ports", event.target.value);
            }}
            onBlur={(event) => event.target.setCustomValidity(portsError)}
            required
            autoFocus={autoFocusField()}
            maxLength={1024}
            error={portsError}
            description={
              total > 0
                ? t(kernel ? "portsSummaryKernel" : "portsSummary")
                    .replace("{n}", number(total, locale))
                    .replace(
                      "{r}",
                      number(kernel ? parsed.spans.length : total, locale),
                    )
                : t("localServerScope")
            }
          />
          <ProtocolField draft={draft} />
        </div>
        {several && (
          <fieldset className="flex min-w-0 flex-col gap-3">
            <legend className="mb-2 flex items-center gap-1 text-sm font-medium">
              {t("portMapping")}
              <HelpTip>{t("portMappingHelp")}</HelpTip>
            </legend>
            <ChoiceCards
              name="port-mode"
              label={t("portMapping")}
              value={mode}
              choices={modes
                .filter((m) => m.id !== "map" || value.engine !== "iptables")
                .map(({ id, icon: Icon, title, help }) => ({
                  id,
                  icon: <Icon />,
                  title: t(title),
                  help: t(help),
                }))}
              onChange={(next) => patch("port_mode", next)}
            />
            {value.engine === "iptables" && (
              <p className="field-hint">{t("portModeMapNft")}</p>
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
                error={remoteError}
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
                {parsed.spans.length > 4 && (
                  <li>… +{parsed.spans.length - 4}</li>
                )}
              </ul>
            )}
          </fieldset>
        )}
      </FormSection>
      <FormSection
        icon={<Tag />}
        title={t("sectionIdentity")}
        description={t("sectionIdentityHelp")}
      >
        <FieldGroup columns>
          <TextField
            id="connection-name"
            label={t("name")}
            optional
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
        <label className="switch-row" htmlFor="connection-enabled">
          <span className="min-w-0 flex-1">
            <span className="block text-sm font-medium">
              {t("startAfterSave")}
            </span>
            <span className="block text-xs text-muted-foreground">
              {t("startAfterSaveHelp")}
            </span>
          </span>
          <Switch
            id="connection-enabled"
            checked={value.enabled}
            onCheckedChange={(next) => patch("enabled", next)}
          />
        </label>
      </FormSection>
    </div>
  );
}
