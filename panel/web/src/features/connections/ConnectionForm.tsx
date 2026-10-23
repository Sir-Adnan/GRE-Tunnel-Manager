import { useState } from "react";
import { ArrowRight, ChevronDown, Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { TextField, Choice } from "@/components/shared";
import { HelpTip, ActionButton } from "@/components/help";
import { engineName } from "@/lib/format";
import { useT } from "@/lib/i18n";
import { endpoint } from "@/lib/api";
import type { Connection, Inventory, Preset } from "@/lib/api";
import { HealthCheckFields } from "./HealthCheckFields";
import { AffinityFields } from "./AffinityFields";
import { RoutingFields } from "./RoutingFields";
import { ProfilePicker } from "./ProfilePicker";

const healthOptionKeys = [
  "check_mode",
  "check_port",
  "check_path",
  "check_host",
  "check_status",
];

type Props = {
  inventory: Inventory;
  engine: string;
  engines?: string[];
  original?: Connection;
  onClose: () => void;
  onSubmit: (request: unknown) => Promise<void>;
};
export function ConnectionForm({
  inventory,
  engine,
  engines,
  original,
  onClose,
  onSubmit,
}: Props) {
  const t = useT();
  const [value, setValue] = useState<Connection>(() =>
    original
      ? structuredClone(original)
      : {
          id: "",
          name: "",
          engine,
          protocol: "tcp",
          bind: ["nftables", "iptables"].includes(engine)
            ? inventory.host.addresses.find((ip) => !ip.includes(":")) || ""
            : "0.0.0.0",
          ports: "",
          strategy: "single",
          enabled: true,
          snat: "masquerade",
          interface: "any",
          targets: [{ ip: "", port: 443, weight: 1 }],
          options: {},
          revision: "",
        },
  );
  const [advanced, setAdvanced] = useState(
    Boolean(
      original?.routing ||
      (original?.options && Object.keys(original.options).length),
    ),
  );
  const [preset, setPreset] = useState("custom");
  const [review, setReview] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const capability = inventory.capabilities.find(
    (item) => item.id === value.engine,
  )!;
  const installed = inventory.components.find(
    (item) => item.id === value.engine,
  )?.installed;
  function patch<K extends keyof Connection>(key: K, next: Connection[K]) {
    setValue((current) => ({ ...current, [key]: next }));
    setReview(false);
  }
  function applyPreset(profile: Preset | undefined) {
    setPreset(profile?.id || "custom");
    if (!profile) return;
    setValue((current) => ({
      ...current,
      protocol: profile.protocol || current.protocol,
      strategy:
        current.targets.length > 1
          ? profile.strategy || current.strategy
          : "single",
      options: { ...current.options, ...profile.options },
    }));
    setReview(false);
  }
  function parseCombinedIP(index: number, input: string) {
    const target = value.targets[index];
    const match =
      input.match(/^\[([^\]]+)\]:(\d+)$/) ||
      input.match(/^(\d+\.\d+\.\d+\.\d+):(\d+)$/);
    patch(
      "targets",
      value.targets.map((item, i) =>
        i === index
          ? {
              ...target,
              ip: match ? match[1] : input,
              ...(match ? { port: Number(match[2]) } : {}),
            }
          : item,
      ),
    );
  }
  async function submit() {
    setBusy(true);
    setError("");
    try {
      await onSubmit({
        action: original ? "update" : "create",
        connection: value,
        ...(original
          ? { selected: [{ id: original.id, revision: original.revision }] }
          : {}),
      });
      onClose();
    } catch (error) {
      setError(String(error instanceof Error ? error.message : error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent
        closeLabel={t("close")}
        className="flex max-h-[calc(100dvh-2rem)] flex-col sm:max-w-2xl"
      >
        <DialogHeader className="shrink-0 pe-7">
          <DialogTitle>
            {t(original ? "edit" : "newConnection")} ·{" "}
            <span dir="ltr">
              {value.engine === "haproxy"
                ? "HAProxy"
                : value.engine === "realm"
                  ? "Realm"
                  : value.engine}
            </span>
          </DialogTitle>
          <DialogDescription>
            {t(review ? "reviewDesc" : "emptyDesc")}
          </DialogDescription>
        </DialogHeader>
        <div className="flex max-h-[60dvh] min-h-0 flex-col gap-4 overflow-y-auto px-1 [scrollbar-width:thin]">
          {error && (
            <Alert>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {!installed && (
            <Alert>
              <AlertDescription>{t("needsInstall")}</AlertDescription>
            </Alert>
          )}
          {review ? (
            <div className="review-block">
              <dl className="review-grid">
                <dt>{t("name")}</dt>
                <dd>{value.name || `${value.engine}-${value.ports}`}</dd>
                <dt>{t("listener")}</dt>
                <dd>
                  <code dir="ltr">
                    {endpoint(value.bind, value.ports)} /{" "}
                    {value.protocol.toUpperCase()}
                  </code>
                </dd>
                <dt>{t("destination")}</dt>
                <dd className="flex flex-col gap-2">
                  {value.targets.map((target, index) => (
                    <code key={index} dir="ltr">
                      {endpoint(target.ip, target.port)} · {t("weight")}{" "}
                      {target.weight}
                    </code>
                  ))}
                </dd>
                <dt>{t("strategy")}</dt>
                <dd>{t(value.strategy)}</dd>
                <dt>{t("status")}</dt>
                <dd>{t(value.enabled ? "configured" : "disabled")}</dd>
              </dl>
              {Object.keys(value.options).length > 0 && (
                <pre className="code-block" dir="ltr">
                  {JSON.stringify(value.options, null, 2)}
                </pre>
              )}
              {value.routing && (
                <div className="mt-4 flex flex-col gap-3 rounded-xl border p-4">
                  <p className="font-medium">
                    {t(`routeMode_${value.routing.mode}`)}
                  </p>
                  {value.routing.certificate && (
                    <p>
                      {t("certificateID")}:{" "}
                      <bdi>{value.routing.certificate}</bdi>
                    </p>
                  )}
                  {value.routing.rules.map((rule, i) => {
                    const destination = value.targets[rule.target - 1];
                    return (
                      <p key={i} className="break-words text-sm" dir="ltr">
                        {rule.host}
                        {rule.prefix || ""} →{" "}
                        {destination
                          ? endpoint(destination.ip, destination.port)
                          : t("invalid")}
                      </p>
                    );
                  })}
                  <p className="text-xs text-muted-foreground">
                    {t(
                      value.routing.mode === "sni"
                        ? "sniHelp"
                        : "httpRoutingHelp",
                    )}
                  </p>
                </div>
              )}
            </div>
          ) : (
            <form
              id="connection-form"
              onSubmit={(event) => {
                event.preventDefault();
                setReview(true);
              }}
            >
              <FieldGroup>
                {!original && (!engines || engines.length > 1) && (
                  <Choice
                    id="engine"
                    label={t("method")}
                    value={value.engine}
                    choices={inventory.capabilities
                      .filter((cap) => !engines || engines.includes(cap.id))
                      .map((cap) => ({
                        value: cap.id,
                        label:
                          cap.id === "haproxy"
                            ? "HAProxy"
                            : cap.id === "realm"
                              ? "Realm"
                              : cap.id,
                      }))}
                    onChange={(next) => {
                      const cap = inventory.capabilities.find(
                        (item) => item.id === next,
                      )!;
                      setValue((current) => ({
                        ...current,
                        engine: next,
                        protocol: cap.protocols.includes(current.protocol)
                          ? current.protocol
                          : cap.protocols[0],
                        strategy: "single",
                        targets: current.targets.slice(0, 1),
                        options: {},
                        bind: ["iptables", "nftables"].includes(next)
                          ? inventory.host.addresses.find(
                              (ip) => !ip.includes(":"),
                            ) || ""
                          : "0.0.0.0",
                      }));
                    }}
                  />
                )}
                <TextField
                  id="connection-name"
                  label={`${t("name")} · ${t("optional")}`}
                  placeholder={`${value.engine}-${value.ports || "443"}`}
                  help={t("autoName")}
                  value={value.name}
                  onChange={(event) => patch("name", event.target.value)}
                  maxLength={40}
                />
                <p className="text-sm text-muted-foreground">
                  {t("connectionEngine")}:{" "}
                  <bdi className="font-medium text-foreground">
                    {engineName(value.engine)}
                  </bdi>
                </p>
                <TextField
                  id="ports"
                  label={t("localPorts")}
                  help={t("portsHelp")}
                  placeholder="443,8443 or 8000-8003"
                  dir="ltr"
                  value={value.ports}
                  onChange={(event) => patch("ports", event.target.value)}
                  required
                  autoFocus
                  maxLength={1024}
                />
                <Choice
                  id="protocol"
                  label={t("protocol")}
                  value={value.protocol}
                  choices={capability.protocols.map((protocol) => ({
                    value: protocol,
                    label: t(protocol),
                  }))}
                  onChange={(next) => patch("protocol", next)}
                />
                {value.targets.map((target, index) => (
                  <div key={index} className="destination-fields">
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
                        parseCombinedIP(index, event.target.value)
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
                    {value.targets.length > 1 && (
                      <>
                        <TextField
                          id={`weight-${index}`}
                          label={t("weight")}
                          help={t("weightHelp")}
                          type="number"
                          min={1}
                          max={256}
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
                        <ActionButton
                          type="button"
                          variant="ghost"
                          size="icon"
                          label={t("delete")}
                          onClick={() =>
                            patch(
                              "targets",
                              value.targets.filter((_, i) => i !== index),
                            )
                          }
                        >
                          <Trash2 />
                        </ActionButton>
                      </>
                    )}
                  </div>
                ))}
                {value.targets.length < 32 && (
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      patch("targets", [
                        ...value.targets,
                        { ip: "", port: value.targets[0].port, weight: 1 },
                      ]);
                      if (value.strategy === "single")
                        patch(
                          "strategy",
                          (inventory.presets || []).find(
                            (p) => p.id === preset && p.engine === value.engine,
                          )?.strategy || capability.strategies[1],
                        );
                    }}
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
                      .filter((item) => item !== "single")
                      .map((strategy) => ({
                        value: strategy,
                        label: t(strategy),
                      }))}
                    onChange={(next) => patch("strategy", next)}
                  />
                )}
                <ProfilePicker
                  presets={(inventory.presets || []).filter(
                    (p) => p.engine === value.engine,
                  )}
                  value={preset}
                  onChange={applyPreset}
                  targetCount={value.targets.length}
                />
                <Button
                  variant="ghost"
                  type="button"
                  className="justify-between"
                  aria-expanded={advanced}
                  onClick={() => setAdvanced(!advanced)}
                >
                  {t("advanced")}
                  <ChevronDown data-icon="inline-end" />
                </Button>
                {advanced && (
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
                          onChange={(event) =>
                            patch("interface", event.target.value)
                          }
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
                    {value.engine === "haproxy" && (
                      <HealthCheckFields
                        options={value.options}
                        onChange={(next) => patch("options", next)}
                      />
                    )}
                    {capability.options
                      .filter(
                        (option) =>
                          value.engine !== "haproxy" ||
                          (!healthOptionKeys.includes(option.key) &&
                            !["stick", "stick_size", "stick_expire"].includes(
                              option.key,
                            )),
                      )
                      .map((option) =>
                        option.choices ? (
                          <Choice
                            key={option.key}
                            id={`option-${option.key}`}
                            label={t(option.key)}
                            value={value.options[option.key] ?? option.default}
                            choices={option.choices.map((id) => ({
                              value: id,
                              label: t(id),
                            }))}
                            onChange={(next) =>
                              patch("options", {
                                ...value.options,
                                [option.key]: next,
                              })
                            }
                          />
                        ) : (
                          <TextField
                            key={option.key}
                            id={`option-${option.key}`}
                            label={t(option.key)}
                            type={option.format ? "text" : "number"}
                            min={option.min}
                            max={option.max}
                            value={value.options[option.key] ?? option.default}
                            onChange={(event) =>
                              patch("options", {
                                ...value.options,
                                [option.key]: event.target.value,
                              })
                            }
                            required
                          />
                        ),
                      )}
                    {capability.options.length > 0 && (
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">
                          {t("proxyGuide")}
                        </span>
                        <HelpTip label={t("proxyGuide")}>
                          {t("proxyHelp")}
                        </HelpTip>
                      </div>
                    )}
                    <Field orientation="horizontal">
                      <FieldLabel htmlFor="connection-enabled">
                        {t("enable")}
                      </FieldLabel>
                      <Switch
                        id="connection-enabled"
                        checked={value.enabled}
                        onCheckedChange={(next) => patch("enabled", next)}
                      />
                    </Field>
                  </FieldGroup>
                )}
              </FieldGroup>
            </form>
          )}
        </div>
        <DialogFooter className="shrink-0">
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => (review ? setReview(false) : onClose())}
          >
            {t(review ? "back" : "cancel")}
          </Button>
          {review ? (
            <Button disabled={busy || !installed} onClick={submit}>
              {t(busy ? "working" : "save")}
            </Button>
          ) : (
            <Button type="submit" form="connection-form" disabled={!installed}>
              {t("review")}
              <ArrowRight data-icon="inline-end" className="rtl:rotate-180" />
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
