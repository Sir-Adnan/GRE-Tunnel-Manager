// The connection list's one-line route: entrance ports, a wire colored by the connection's state and its
// destinations. Words stay readable for screen readers; addresses and ports are always isolated LTR.
import { Check, CircleX, Clock3, Power, TriangleAlert } from "lucide-react";
import { useT } from "@/lib/i18n";
import type { Connection } from "@/lib/api";
import { toneLabel, type Tone } from "@/lib/connection-tone";
import { Destinations } from "./Destinations";

const icons = {
  ok: Check,
  warn: TriangleAlert,
  problem: CircleX,
  off: Power,
  pending: Clock3,
} as const;

/** A square icon chip that names the connection's state; color is never the only cue. */
export function StatusChip({ tone }: { tone: Tone }) {
  const t = useT();
  const Icon = icons[tone];
  const label = t(toneLabel[tone]);
  return (
    <span
      className="status-chip"
      data-tone={tone}
      role="img"
      aria-label={label}
      title={label}
    >
      <Icon aria-hidden />
    </span>
  );
}

function protocolName(protocol: string) {
  return protocol === "both" ? "TCP+UDP" : protocol.toUpperCase();
}

export function RouteChain({
  connection,
  tone,
}: {
  connection: Connection;
  tone: Tone;
}) {
  const t = useT();
  return (
    <div className="route-chain" data-tone={tone}>
      <span className="chain-node">
        <span className="sr-only">{t("listener")}: </span>
        <bdi dir="ltr" className="chain-ports">
          <span className="chain-protocol">
            {protocolName(connection.protocol)}
          </span>{" "}
          :{connection.ports}
        </bdi>
      </span>
      <span className="chain-wire" aria-hidden />
      <span className="chain-node is-target">
        <span className="sr-only">{t("destination")}: </span>
        <Destinations connection={connection} />
      </span>
    </div>
  );
}
