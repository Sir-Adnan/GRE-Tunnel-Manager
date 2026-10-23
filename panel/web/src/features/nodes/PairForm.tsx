import { useState } from "react";
import { api } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { Choice, TextField } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { FieldGroup } from "@/components/ui/field";
import type { Node } from "./types";

const eligible = (n: Node) =>
  n.status === "online" && n.capabilities.includes("connections.pair.v1");
function requestID() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}
const address = (n?: Node) =>
  n?.inventory?.host.public_ip || n?.inventory?.host.addresses?.[0] || "";

export function PairForm({
  nodes,
  onCreated,
  onClose,
}: {
  nodes: Node[];
  onCreated: () => void;
  onClose: () => void;
}) {
  const t = useT();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [review, setReview] = useState(false);
  const [id] = useState(requestID);
  const [kind, setKind] = useState("gre");
  const [name, setName] = useState("");
  const [entrance, setEntrance] = useState(nodes.filter(eligible)[0]?.id || "");
  const [destination, setDestination] = useState(
    nodes.filter(eligible)[1]?.id || "",
  );
  const [entranceIP, setEntranceIP] = useState(
    address(nodes.filter(eligible)[0]),
  );
  const [destinationIP, setDestinationIP] = useState(
    address(nodes.filter(eligible)[1]),
  );
  const [greID, setGREID] = useState("1");
  const [mtu, setMTU] = useState("1430");
  const [controlPort, setControlPort] = useState("7000");
  const [publicPort, setPublicPort] = useState("443");
  const [localIP, setLocalIP] = useState("127.0.0.1");
  const [localPort, setLocalPort] = useState("443");
  const [protocol, setProtocol] = useState("tcp");
  const [transport, setTransport] = useState("tcp");
  const choices = nodes
    .filter(eligible)
    .map((n) => ({ value: n.id, label: n.name }));
  const nodeName = (id: string) => nodes.find((n) => n.id === id)?.name || id;
  const choose = (value: string, side: "entrance" | "destination") => {
    const n = nodes.find((n) => n.id === value);
    if (side === "entrance") {
      setEntrance(value);
      setEntranceIP(address(n));
    } else {
      setDestination(value);
      setDestinationIP(address(n));
    }
  };
  const payload = () => ({
    id,
    name: name.trim(),
    kind,
    entrance: {
      id: entrance,
      revision: nodes.find((n) => n.id === entrance)?.revision || "",
      address: entranceIP.trim(),
    },
    destination: {
      id: destination,
      revision: nodes.find((n) => n.id === destination)?.revision || "",
      address: kind === "gre" ? destinationIP.trim() : "",
    },
    ...(kind === "gre"
      ? { gre_id: Number(greID), mtu: Number(mtu) }
      : {
          control_port: Number(controlPort),
          public_port: Number(publicPort),
          local_ip: localIP.trim(),
          local_port: Number(localPort),
          protocol,
          transport,
        }),
  });
  async function perform(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog
      open
      onOpenChange={(value) => {
        if (!busy && !value) onClose();
      }}
    >
      <DialogContent className="sm:max-w-2xl" closeLabel={t("close")}>
        <DialogHeader>
          <DialogTitle>{t(review ? "pairReview" : "pairCreate")}</DialogTitle>
          <DialogDescription>
            {t(review ? "pairReviewHelp" : "pairFormHelp")}
          </DialogDescription>
        </DialogHeader>
        <form
          className="flex min-h-0 flex-col gap-5"
          onSubmit={(event) => {
            event.preventDefault();
            if (busy) return;
            if (!review) {
              setReview(true);
              return;
            }
            void perform(async () => {
              await api("nodes/pairs", payload());
              onCreated();
            });
          }}
        >
          <div className="flex max-h-[55dvh] flex-col gap-5 overflow-auto [scrollbar-width:thin]">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            {!review ? (
              <FieldGroup>
                <Choice
                  id="pair-kind"
                  label={t("type")}
                  value={kind}
                  onChange={setKind}
                  choices={[
                    { value: "gre", label: "GRE" },
                    { value: "frp", label: "FRP Reverse" },
                  ]}
                />
                <TextField
                  id="pair-name"
                  label={t("name")}
                  help={t("pairNameHelp")}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  maxLength={64}
                />
                <FieldGroup className="md:grid md:grid-cols-2">
                  <Choice
                    id="pair-entrance"
                    label={t("pairEntrance")}
                    value={entrance}
                    onChange={(v) => choose(v, "entrance")}
                    choices={choices}
                  />
                  <Choice
                    id="pair-destination"
                    label={t("pairDestination")}
                    value={destination}
                    onChange={(v) => choose(v, "destination")}
                    choices={choices}
                  />
                  <TextField
                    id="pair-entrance-ip"
                    label={t("pairEntranceIP")}
                    help={t("pairAddressHelp")}
                    value={entranceIP}
                    onChange={(e) => setEntranceIP(e.target.value)}
                    dir="ltr"
                    required
                  />
                  {kind === "gre" && (
                    <TextField
                      id="pair-destination-ip"
                      label={t("pairDestinationIP")}
                      value={destinationIP}
                      onChange={(e) => setDestinationIP(e.target.value)}
                      dir="ltr"
                      required
                    />
                  )}
                </FieldGroup>
                {kind === "gre" ? (
                  <FieldGroup className="md:grid md:grid-cols-2">
                    <TextField
                      id="pair-gre-id"
                      label={t("tunnelId")}
                      value={greID}
                      type="number"
                      min={1}
                      max={250}
                      onChange={(e) => setGREID(e.target.value)}
                      required
                    />
                    <TextField
                      id="pair-mtu"
                      label="MTU"
                      value={mtu}
                      type="number"
                      min={1280}
                      max={1472}
                      onChange={(e) => setMTU(e.target.value)}
                      required
                    />
                  </FieldGroup>
                ) : (
                  <FieldGroup className="md:grid md:grid-cols-2">
                    <TextField
                      id="pair-public-port"
                      label={t("pairPublicPort")}
                      value={publicPort}
                      type="number"
                      min={1}
                      max={65535}
                      onChange={(e) => setPublicPort(e.target.value)}
                      required
                    />
                    <TextField
                      id="pair-control-port"
                      label={t("pairControlPort")}
                      value={controlPort}
                      type="number"
                      min={1}
                      max={65535}
                      onChange={(e) => setControlPort(e.target.value)}
                      required
                    />
                    <TextField
                      id="pair-local-ip"
                      label={t("pairServiceIP")}
                      value={localIP}
                      dir="ltr"
                      onChange={(e) => setLocalIP(e.target.value)}
                      required
                    />
                    <TextField
                      id="pair-local-port"
                      label={t("pairServicePort")}
                      value={localPort}
                      type="number"
                      min={1}
                      max={65535}
                      onChange={(e) => setLocalPort(e.target.value)}
                      required
                    />
                    <Choice
                      id="pair-protocol"
                      label={t("protocol")}
                      value={protocol}
                      onChange={setProtocol}
                      choices={[
                        { value: "tcp", label: "TCP" },
                        { value: "udp", label: "UDP" },
                      ]}
                    />
                    <Choice
                      id="pair-transport"
                      label={t("transport")}
                      value={transport}
                      onChange={setTransport}
                      choices={[
                        { value: "tcp", label: "TCP" },
                        { value: "websocket", label: "WebSocket" },
                        { value: "quic", label: "QUIC" },
                      ]}
                    />
                  </FieldGroup>
                )}
              </FieldGroup>
            ) : (
              <div className="flex flex-col gap-4">
                <p className="text-sm font-medium [overflow-wrap:anywhere]">
                  {kind.toUpperCase()} · {name || t("pairAutoName")}
                </p>
                <div className="grid min-w-0 gap-3 md:grid-cols-2">
                  {[
                    [entrance, entranceIP],
                    [destination, kind === "gre" ? destinationIP : ""],
                  ].map(([n, ip]) => (
                    <div key={n} className="flex min-w-0 flex-col gap-1">
                      <bdi className="[overflow-wrap:anywhere]">
                        {nodeName(n)}
                      </bdi>
                      {ip && (
                        <bdi dir="ltr" className="break-all font-mono text-sm">
                          {ip}
                        </bdi>
                      )}
                    </div>
                  ))}
                </div>
                <p className="text-sm">
                  <bdi dir="ltr">
                    {kind === "gre"
                      ? `GRE ${greID} · MTU ${mtu}`
                      : `${protocol.toUpperCase()} / ${transport.toUpperCase()} · ${publicPort} → ${localIP}:${localPort} · ${controlPort}`}
                  </bdi>
                </p>
                <Alert>
                  <AlertDescription>
                    {t(kind === "gre" ? "pairGREHelp" : "pairFRPHelp")}
                  </AlertDescription>
                </Alert>
              </div>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            {review && (
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={() => setReview(false)}
              >
                {t("back")}
              </Button>
            )}
            <Button
              type="submit"
              disabled={
                busy || !entrance || !destination || entrance === destination
              }
            >
              {t(review ? "pairStart" : "pairReview")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
