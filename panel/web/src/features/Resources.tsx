import { useState } from "react";
import {
  FileText,
  Play,
  Plus,
  RotateCw,
  Square,
  Trash2,
  Pencil,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { FieldGroup, Field, FieldLabel } from "@/components/ui/field";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Blank,
  Choice,
  PageTitle,
  Status,
  TextField,
} from "@/components/shared";
import { ActionButton } from "@/components/help";
import { useT } from "@/lib/i18n";
import type { Inventory, Resource } from "@/lib/api";

export function Resources({
  inventory,
  engine,
  run,
}: {
  inventory: Inventory;
  engine: "gre" | "reverse";
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<Resource>();
  const [busy, setBusy] = useState(false);
  const [renaming, setRenaming] = useState<Resource>();
  const [displayName, setDisplayName] = useState("");
  const [renameError, setRenameError] = useState("");
  const shown = inventory.resources.filter((r) =>
    engine === "gre" ? r.engine === "gre" : r.engine !== "gre",
  );
  async function remove() {
    if (!deleting) return;
    setBusy(true);
    try {
      await run({
        action: engine === "gre" ? "gre-delete" : "reverse-delete",
        service: deleting.id,
      });
      setDeleting(undefined);
    } catch {
      /* global operation feedback */
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="page-stack">
      <PageTitle
        title={t(engine)}
        description={t(engine === "gre" ? "greDesc" : "reverseDesc")}
        action={
          <Button onClick={() => setCreating(true)}>
            <Plus data-icon="inline-start" />
            {t("add")}
          </Button>
        }
      />
      {shown.length === 0 ? (
        <Card>
          <CardContent>
            <Blank onAdd={() => setCreating(true)} />
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
          {shown.map((resource) => (
            <Card key={resource.id}>
              <CardHeader>
                <div className="flex items-center justify-between gap-2">
                  <CardTitle>{resource.name}</CardTitle>
                  <Status value={resource.status} />
                </div>
                <CardDescription>
                  <span dir="ltr">
                    {resource.engine.toUpperCase()} · {resource.role}
                  </span>
                </CardDescription>
              </CardHeader>
              <CardContent>
                <code className="text-xs text-muted-foreground" dir="ltr">
                  {resource.id}
                </code>
                {resource.interface && (
                  <p className="mt-3 text-sm" dir="ltr">
                    {resource.interface}
                  </p>
                )}
              </CardContent>
              <CardFooter className="flex flex-wrap gap-1">
                <ActionButton
                  variant="ghost"
                  size="icon"
                  label={t("renameDisplay")}
                  onClick={() => {
                    setRenaming(resource);
                    setDisplayName(resource.name);
                    setRenameError("");
                  }}
                >
                  <Pencil />
                </ActionButton>
                {[
                  ["start", Play],
                  ["stop", Square],
                  ["restart", RotateCw],
                  ["logs", FileText],
                ].map(([action, Icon]) => {
                  const name = action as string;
                  const Glyph = Icon as typeof Play;
                  return (
                    <ActionButton
                      key={name}
                      variant="ghost"
                      size="icon"
                      label={t(name)}
                      onClick={() =>
                        void run({
                          action: name === "logs" ? "logs" : "service",
                          service: resource.id,
                          verb: name,
                        }).catch(() => {})
                      }
                    >
                      <Glyph />
                    </ActionButton>
                  );
                })}
                <ActionButton
                  variant="ghost"
                  size="icon"
                  label={t("delete")}
                  onClick={() => setDeleting(resource)}
                >
                  <Trash2 />
                </ActionButton>
              </CardFooter>
            </Card>
          ))}
        </div>
      )}
      {creating && (
        <ResourceForm
          inventory={inventory}
          engine={engine}
          run={run}
          onClose={() => setCreating(false)}
        />
      )}
      <Dialog
        open={Boolean(renaming)}
        onOpenChange={(open) => !open && !busy && setRenaming(undefined)}
      >
        <DialogContent closeLabel={t("close")}>
          <DialogHeader>
            <DialogTitle>{t("renameDisplay")}</DialogTitle>
            <DialogDescription>{t("renameHelp")}</DialogDescription>
          </DialogHeader>
          <form
            id="rename-resource"
            onSubmit={async (e) => {
              e.preventDefault();
              if (!renaming) return;
              setBusy(true);
              setRenameError("");
              try {
                await run({
                  action: "resource-rename",
                  resource_name: {
                    id: renaming.id,
                    revision: renaming.revision,
                    name: displayName,
                  },
                });
                setRenaming(undefined);
              } catch (e) {
                setRenameError(String(e));
              } finally {
                setBusy(false);
              }
            }}
          >
            <TextField
              id="resource-display-name"
              label={t("name")}
              value={displayName}
              maxLength={40}
              pattern="[a-zA-Z0-9][a-zA-Z0-9_. \-]{0,39}"
              onChange={(e) => setDisplayName(e.target.value)}
            />
            {renameError && (
              <p role="alert" className="mt-3 text-sm text-destructive">
                {renameError}
              </p>
            )}
          </form>
          <DialogFooter>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setRenaming(undefined)}
            >
              {t("cancel")}
            </Button>
            <Button type="submit" form="rename-resource" disabled={busy}>
              {t(busy ? "working" : "save")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog
        open={Boolean(deleting)}
        onOpenChange={(open) => !open && !busy && setDeleting(undefined)}
      >
        <DialogContent closeLabel={t("close")}>
          <DialogHeader>
            <DialogTitle>
              {t("delete")} · {deleting?.name}
            </DialogTitle>
            <DialogDescription>{t("reviewDesc")}</DialogDescription>
          </DialogHeader>
          <code dir="ltr">{deleting?.id}</code>
          <DialogFooter>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setDeleting(undefined)}
            >
              {t("cancel")}
            </Button>
            <Button variant="destructive" disabled={busy} onClick={remove}>
              {t(busy ? "working" : "delete")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
function ResourceForm({
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
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent
        closeLabel={t("close")}
        className="form-dialog sm:max-w-xl"
      >
        <DialogHeader>
          <DialogTitle>
            {t("add")} · {engine === "gre" ? "GRE" : "Reverse"}
          </DialogTitle>
          <DialogDescription>
            {t(engine === "gre" ? "greHelp" : "reverseHelp")}
          </DialogDescription>
        </DialogHeader>
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
            <FieldGroup>
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
                      onChange={(event) => change("token", event.target.value)}
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
                      <Button
                        variant="ghost"
                        type="button"
                        onClick={() =>
                          navigator.clipboard.writeText(reverse.token)
                        }
                      >
                        {t("copy")} · {t("token")}
                      </Button>
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
                        onChange={(event) => change("key", event.target.value)}
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
        <DialogFooter>
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => (review ? setReview(false) : onClose())}
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
  );
}
