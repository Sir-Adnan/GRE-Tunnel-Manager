import { useState } from "react";
import { CopyButton } from "@/components/CopyButton";
import { ProfilePicker } from "../connections/ProfilePicker";
import { Button } from "@/components/ui/button";
import { FieldGroup, Field, FieldLabel } from "@/components/ui/field";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogBody,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { TextField, Choice, Address } from "@/components/shared";
import { useT } from "@/lib/i18n";
import { useDiscardChanges } from "@/lib/use-discard-changes";
import type { Inventory, Preset } from "@/lib/api";
export function ResourceForm({
  inventory,
  engine,
  run,
  onClose,
}: {
  inventory: Inventory;
  engine: "gre" | "reverse";
  run: (request: unknown) => Promise<void>;
  onClose: () => void;
}) {
  const t = useT();
  const local = inventory.host.addresses.find((ip) => !ip.includes(":")) || "";
  const [gre, setGRE] = useState({
    id: 1,
    role: "kharej",
    remote: "",
    bind: local,
    mtu: 1430,
  });
  const [reverse, setReverse] = useState({
    engine: "frp",
    name: "",
    role: "entrance",
    host: local,
    control: 7000,
    public: 443,
    local_ip: "127.0.0.1",
    local_port: 443,
    protocol: "tcp",
    transport: "tcp",
    mux: true,
    token: "",
    group: "tunnel",
    key: "",
    certificate: "",
    internal: 7001,
  });
  const [profile, setProfile] = useState("custom");
  function applyProfile(p: Preset | undefined) {
    setProfile(p?.id || "custom");
    if (!p) return;
    if (engine === "gre")
      setGRE((current) => ({ ...current, mtu: p.mtu || current.mtu }));
    else
      setReverse((current) => ({
        ...current,
        engine: p.engine,
        protocol: p.protocol || current.protocol,
        transport: p.transport || current.transport,
        mux: p.mux ?? current.mux,
      }));
  }
  const [baseline] = useState(() => JSON.stringify({ gre, reverse }));
  const { requestClose, confirmation } = useDiscardChanges(
    JSON.stringify({ gre, reverse }) !== baseline,
    onClose,
  );
  const [review, setReview] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const installed =
    engine === "gre" ||
    inventory.components.find((c) => c.id === reverse.engine)?.installed;
  const change = <K extends keyof typeof reverse>(
    key: K,
    value: (typeof reverse)[K],
  ) => setReverse((current) => ({ ...current, [key]: value }));
  async function submit() {
    setBusy(true);
    setError("");
    try {
      await run(
        engine === "gre"
          ? { action: "gre-create", gre }
          : {
              action: "reverse-create",
              reverse: {
                ...reverse,
                name: reverse.name || `tunnel-${reverse.public}`,
              },
            },
      );
      onClose();
    } catch (error) {
      setError(String(error instanceof Error ? error.message : error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Dialog open onOpenChange={(open) => !open && !busy && requestClose()}>
        <DialogContent
          closeLabel={t("close")}
          scrollLayout="body"
          className="dialog-shell sm:max-w-2xl"
        >
          <DialogHeader>
            <DialogTitle>
              {t("add")} · {engine === "gre" ? "GRE" : "Reverse"}
            </DialogTitle>
            <DialogDescription>
              {t(engine === "gre" ? "greHelp" : "reverseHelp")}
            </DialogDescription>
            <div className="flex flex-wrap gap-1">
              {inventory.host.addresses.slice(0, 2).map((ip) => (
                <Address key={ip}>{ip}</Address>
              ))}
            </div>
          </DialogHeader>
          <DialogBody key={review ? "review" : "form"}>
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
                <p className="mb-4 text-sm text-muted-foreground">
                  {t("reviewDesc")}
                </p>
                <dl className="review-grid">
                  {Object.entries(
                    engine === "gre"
                      ? gre
                      : {
                          method: reverse.engine,
                          name: reverse.name || `tunnel-${reverse.public}`,
                          role: reverse.role,
                          host: reverse.host,
                          publicPort: reverse.public,
                          controlPort: reverse.control,
                          transport:
                            reverse.engine === "rathole"
                              ? "Noise NK / TCP"
                              : reverse.transport,
                          protocol: reverse.protocol,
                        },
                  ).map(([key, value]) => (
                    <div key={key} className="contents">
                      <dt>{t(key)}</dt>
                      <dd>
                        <bdi>{String(value)}</bdi>
                      </dd>
                    </div>
                  ))}
                </dl>
              </div>
            ) : (
              <form
                id="resource-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  setReview(true);
                }}
              >
                <FieldGroup columns>
                  <ProfilePicker
                    presets={(inventory.presets || []).filter((p) =>
                      engine === "gre"
                        ? p.engine === "gre"
                        : p.engine === reverse.engine,
                    )}
                    value={profile}
                    onChange={applyProfile}
                  />
                  {engine === "gre" ? (
                    <>
                      <TextField
                        id="gre-id"
                        label={t("tunnelID")}
                        type="number"
                        min={1}
                        max={250}
                        value={gre.id}
                        onChange={(event) =>
                          setGRE({ ...gre, id: Number(event.target.value) })
                        }
                        required
                      />
                      <Choice
                        id="gre-role"
                        label={t("role")}
                        value={gre.role}
                        choices={[
                          { value: "kharej", label: "Kharej / Side A" },
                          { value: "iran", label: "Iran / Side B" },
                        ]}
                        onChange={(role) => setGRE({ ...gre, role })}
                      />
                      <TextField
                        id="gre-peer"
                        label={t("peerIP")}
                        dir="ltr"
                        value={gre.remote}
                        onChange={(event) =>
                          setGRE({ ...gre, remote: event.target.value })
                        }
                        required
                      />
                      <TextField
                        id="gre-bind"
                        label={t("bind")}
                        dir="ltr"
                        value={gre.bind}
                        onChange={(event) =>
                          setGRE({ ...gre, bind: event.target.value })
                        }
                        required
                      />
                      <TextField
                        id="gre-mtu"
                        label={t("mtu")}
                        type="number"
                        min={1280}
                        max={gre.remote.includes(":") ? 1452 : 1472}
                        value={gre.mtu}
                        onChange={(event) =>
                          setGRE({ ...gre, mtu: Number(event.target.value) })
                        }
                        required
                      />
                    </>
                  ) : (
                    <>
                      <Choice
                        id="reverse-engine"
                        label={t("method")}
                        value={reverse.engine}
                        choices={[
                          { value: "frp", label: "FRP" },
                          { value: "rathole", label: "rathole · Noise NK" },
                        ]}
                        onChange={(value) =>
                          setReverse((current) => ({
                            ...current,
                            engine: value,
                            protocol: "tcp",
                          }))
                        }
                      />
                      <Choice
                        id="reverse-role"
                        label={t("role")}
                        value={reverse.role}
                        choices={[
                          { value: "entrance", label: t("entrance") },
                          { value: "destination", label: t("destinationRole") },
                        ]}
                        onChange={(value) => change("role", value)}
                      />
                      <div className="grid gap-4 sm:grid-cols-2">
                        <TextField
                          id="reverse-public"
                          label={t("publicPort")}
                          type="number"
                          min={1}
                          max={65535}
                          value={reverse.public}
                          onChange={(event) =>
                            change("public", Number(event.target.value))
                          }
                          required
                        />
                        <TextField
                          id="reverse-control"
                          label={t("controlPort")}
                          type="number"
                          min={1}
                          max={65535}
                          value={reverse.control}
                          onChange={(event) =>
                            change("control", Number(event.target.value))
                          }
                          required
                        />
                      </div>
                      <TextField
                        id="reverse-host"
                        label={t("host")}
                        value={reverse.host}
                        onChange={(event) => change("host", event.target.value)}
                        dir="ltr"
                        required
                      />
                      <Choice
                        id="reverse-protocol"
                        label={t("protocol")}
                        value={reverse.protocol}
                        choices={(reverse.engine === "frp"
                          ? ["tcp", "udp"]
                          : ["tcp", "udp", "both"]
                        ).map((value) => ({ value, label: t(value) }))}
                        onChange={(value) => change("protocol", value)}
                      />
                      <TextField
                        id="reverse-name"
                        label={t("name")}
                        placeholder={`tunnel-${reverse.public}`}
                        value={reverse.name}
                        onChange={(event) => change("name", event.target.value)}
                        pattern="[a-zA-Z0-9_\-]{1,32}"
                        maxLength={32}
                      />
                      <FieldGroup>
                        <TextField
                          id="reverse-token"
                          label={t("token")}
                          type="password"
                          value={reverse.token}
                          onChange={(event) =>
                            change("token", event.target.value)
                          }
                          minLength={24}
                          maxLength={128}
                          pattern="[a-zA-Z0-9_\-]{24,128}"
                          required
                          autoComplete="new-password"
                        />
                        <Button
                          type="button"
                          variant="outline"
                          onClick={() => {
                            const bytes = crypto.getRandomValues(
                              new Uint8Array(32),
                            );
                            change(
                              "token",
                              Array.from(bytes, (value) =>
                                value.toString(16).padStart(2, "0"),
                              ).join(""),
                            );
                          }}
                        >
                          {t("generate")}
                        </Button>
                        {reverse.token && (
                          <CopyButton
                            variant="ghost"
                            type="button"
                            text={reverse.token}
                            label={`${t("copy")} · ${t("token")}`}
                          />
                        )}
                      </FieldGroup>
                      {reverse.role === "destination" && (
                        <>
                          <TextField
                            id="reverse-local-ip"
                            label={t("localIP")}
                            dir="ltr"
                            value={reverse.local_ip}
                            onChange={(event) =>
                              change("local_ip", event.target.value)
                            }
                            required
                          />
                          <TextField
                            id="reverse-local-port"
                            label={t("localPort")}
                            type="number"
                            min={1}
                            max={65535}
                            value={reverse.local_port}
                            onChange={(event) =>
                              change("local_port", Number(event.target.value))
                            }
                            required
                          />
                        </>
                      )}
                      {reverse.engine === "frp" ? (
                        <>
                          <Choice
                            id="reverse-transport"
                            label={t("transport")}
                            value={reverse.transport}
                            choices={[
                              { value: "tcp", label: "TCP" },
                              { value: "websocket", label: "WebSocket" },
                              { value: "wss", label: "WSS · TLS gateway" },
                              { value: "quic", label: "QUIC" },
                            ]}
                            onChange={(value) => change("transport", value)}
                          />
                          <Field orientation="horizontal">
                            <FieldLabel htmlFor="reverse-mux">
                              {t("mux")}
                            </FieldLabel>
                            <Switch
                              id="reverse-mux"
                              checked={reverse.mux}
                              onCheckedChange={(value) => change("mux", value)}
                            />
                          </Field>
                          <TextField
                            id="reverse-group"
                            label={t("group")}
                            value={reverse.group}
                            onChange={(event) =>
                              change("group", event.target.value)
                            }
                            required
                            pattern="[a-zA-Z0-9_\-]{1,32}"
                          />
                          {reverse.transport === "wss" && (
                            <>
                              <TextField
                                id="reverse-cert"
                                label={t("certificate")}
                                dir="ltr"
                                value={reverse.certificate}
                                onChange={(event) =>
                                  change("certificate", event.target.value)
                                }
                                required
                              />
                              <TextField
                                id="reverse-internal"
                                label={t("internalPort")}
                                type="number"
                                min={1}
                                max={65535}
                                value={reverse.internal}
                                onChange={(event) =>
                                  change("internal", Number(event.target.value))
                                }
                                required
                              />
                            </>
                          )}
                        </>
                      ) : (
                        reverse.role === "destination" && (
                          <TextField
                            id="noise-public-key"
                            label={t("noiseKey")}
                            dir="ltr"
                            value={reverse.key}
                            onChange={(event) =>
                              change("key", event.target.value)
                            }
                            required
                            maxLength={44}
                          />
                        )
                      )}
                    </>
                  )}
                </FieldGroup>
              </form>
            )}
          </DialogBody>
          <DialogFooter>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => (review ? setReview(false) : requestClose())}
            >
              {t(review ? "back" : "cancel")}
            </Button>
            {review ? (
              <Button onClick={submit} disabled={busy || !installed}>
                {t(busy ? "working" : "save")}
              </Button>
            ) : (
              <Button type="submit" form="resource-form" disabled={!installed}>
                {t("review")}
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {confirmation}
    </>
  );
}
