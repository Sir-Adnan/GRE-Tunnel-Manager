import { Plus, Trash2, ArrowRight, RadioTower, Server } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Field,
  FieldGroup,
  FieldSet,
  FieldLegend,
  FieldLabel,
  FieldContent,
} from "@/components/ui/field";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Switch } from "@/components/ui/switch";
import { TextField, Choice } from "@/components/shared";
import { ActionButton, HelpTip } from "@/components/help";
import { useT } from "@/lib/i18n";
import type { Inventory } from "@/lib/api";
import { engineName } from "@/lib/format";
import { ProfilePicker } from "./ProfilePicker";
import type { ConnectionDraft } from "./useConnectionDraft";

export function ConnectionBasics({
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
  const t = useT();
  const { value, patch, capability } = draft;
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
      <div className="connection-path">
        <FieldSet className="connection-path-side">
          <FieldLegend>
            <span className="inline-flex items-center gap-2">
              <RadioTower className="size-4" />
              {t("listenerSide")}
            </span>
          </FieldLegend>
          <FieldGroup>
            <TextField
              id="ports"
              label={t("localPorts")}
              help={t("portsHelp")}
              placeholder="443,8443,8000-8003"
              dir="ltr"
              value={value.ports}
              onChange={(event) => patch("ports", event.target.value)}
              required
              autoFocus
              maxLength={1024}
            />
            <Field>
              <FieldLabel>{t("protocol")}</FieldLabel>
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
            <p className="text-xs text-muted-foreground">
              {t("localServerScope")}
            </p>
          </FieldGroup>
        </FieldSet>
        <ArrowRight
          className="connection-path-arrow rtl:rotate-180"
          aria-hidden
        />
        <FieldSet className="connection-path-side">
          <FieldLegend>
            <span className="inline-flex items-center gap-2">
              <Server className="size-4" />
              {t("destinations")}
            </span>
          </FieldLegend>
          <FieldGroup>
            {value.targets.map((target, index) => (
              <FieldGroup key={index} className="target-editor">
                <div className="target-address">
                  <TextField
                    id={`ip-${index}`}
                    label={`${t("remoteIP")}${value.targets.length > 1 ? ` ${index + 1}` : ""}`}
                    placeholder="198.51.100.20"
                    dir="ltr"
                    value={target.ip}
                    onChange={(event) =>
                      patch(
                        "targets",
                        value.targets.map((item, i) =>
                          i === index
                            ? { ...item, ip: event.target.value }
                            : item,
                        ),
                      )
                    }
                    onBlur={(event) =>
                      draft.parseCombinedIP(index, event.target.value)
                    }
                    required
                    maxLength={80}
                  />
                  <TextField
                    id={`port-${index}`}
                    label={t("remotePort")}
                    type="number"
                    min={1}
                    max={65535}
                    dir="ltr"
                    value={target.port}
                    onChange={(event) =>
                      patch(
                        "targets",
                        value.targets.map((item, i) =>
                          i === index
                            ? { ...item, port: Number(event.target.value) }
                            : item,
                        ),
                      )
                    }
                    required
                  />
                </div>
                {value.targets.length > 1 && (
                  <div className="flex items-end justify-between gap-3">
                    <div className="w-36">
                      <TextField
                        id={`weight-${index}`}
                        label={t("weight")}
                        help={t("weightHelp")}
                        type="number"
                        min={1}
                        max={256}
                        required
                        dir="ltr"
                        value={target.weight}
                        onChange={(event) =>
                          patch(
                            "targets",
                            value.targets.map((item, i) =>
                              i === index
                                ? {
                                    ...item,
                                    weight: Number(event.target.value),
                                  }
                                : item,
                            ),
                          )
                        }
                      />
                    </div>
                    <ActionButton
                      type="button"
                      variant="ghost"
                      size="icon"
                      label={`${t("removeDestination")} ${index + 1}`}
                      onClick={() =>
                        patch(
                          "targets",
                          value.targets.filter((_, i) => i !== index),
                        )
                      }
                    >
                      <Trash2 />
                    </ActionButton>
                  </div>
                )}
              </FieldGroup>
            ))}
            {value.targets.length < 32 && (
              <Button
                type="button"
                variant="outline"
                className="self-start"
                onClick={draft.addTarget}
              >
                <Plus data-icon="inline-start" />
                {t("addTarget")}
              </Button>
            )}
            {value.targets.length > 1 && (
              <Choice
                id="strategy"
                label={t("strategy")}
                value={
                  value.strategy === "single"
                    ? capability.strategies[1]
                    : value.strategy
                }
                choices={capability.strategies
                  .filter((s) => s !== "single")
                  .map((s) => ({ value: s, label: t(s) }))}
                onChange={(next) => patch("strategy", next)}
              />
            )}
          </FieldGroup>
        </FieldSet>
      </div>
      <FieldGroup columns>
        <TextField
          id="connection-name"
          label={`${t("name")} · ${t("optional")}`}
          placeholder={`${value.engine}-${value.ports || "443"}`}
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
