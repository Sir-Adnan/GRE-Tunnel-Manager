// The host firewall at a glance: UFW, both iptables backends, nftables and
// the host facts the rules depend on (uplink, SSH, Docker, firewalld).
import { Boxes, Layers, Network, ShieldHalf } from "lucide-react";
import type { ReactNode } from "react";
import { HelpTip } from "@/components/help";
import { useT } from "@/lib/i18n";
import type { FirewallStatus } from "./model";
import { Pill, type Tone } from "./parts";

function Tile({
  icon,
  title,
  tone,
  value,
  help,
  children,
}: {
  icon: ReactNode;
  title: string;
  tone: Tone;
  value: ReactNode;
  help?: string;
  children?: ReactNode;
}) {
  return (
    <section className="fw-tile" data-tone={tone}>
      <header className="fw-tile-head">
        <span className="fw-tile-icon" aria-hidden>
          {icon}
        </span>
        <h3 className="fw-tile-title">{title}</h3>
        {help && <HelpTip label={`${title} · ?`}>{help}</HelpTip>}
      </header>
      <div className="fw-tile-value">{value}</div>
      {children && <dl className="fw-facts">{children}</dl>}
    </section>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="fw-fact">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

export function StatusTiles({ status }: { status: FirewallStatus }) {
  const t = useT();
  const policy = (p: string) => (p ? t(`fwPolicy_${p}`) : "—");
  const ufwTone: Tone = status.ufw.state === "active" ? "ok" : "muted";
  const backendTone: Tone = status.backends.some(
    (b) => b.forward === "DROP" && !b.guard,
  )
    ? "warn"
    : "ok";
  return (
    <div className="fw-tiles">
      <Tile
        icon={<ShieldHalf />}
        title={t("fwUFW")}
        tone={ufwTone}
        value={<Pill tone={ufwTone}>{t(`fwUFW_${status.ufw.state}`)}</Pill>}
      >
        {status.ufw.state !== "missing" && (
          <>
            <Fact label={t("fwIncoming")}>{policy(status.ufw.incoming)}</Fact>
            <Fact label={t("fwRouted")}>{policy(status.ufw.routed)}</Fact>
          </>
        )}
      </Tile>
      <Tile
        icon={<Layers />}
        title={t("fwBackends")}
        tone={backendTone}
        help={t("fwBackendsHelp")}
        value={
          <span className="fw-tile-number">
            <bdi dir="ltr">{status.backends.length}</bdi>
          </span>
        }
      >
        {status.backends.map((b) => (
          <Fact
            key={`${b.family}-${b.tool}`}
            label={`${b.tool} · IPv${b.family}`}
          >
            <span className="fw-backend">
              <bdi dir="ltr" className="font-mono text-xs">
                {t("fwForward")} {b.forward || "—"}
              </bdi>
              {b.forward === "DROP" && (
                <Pill tone={b.guard ? "ok" : "problem"}>
                  {t(b.guard ? "fwGuardOn" : "fwGuardOff")}
                </Pill>
              )}
            </span>
          </Fact>
        ))}
      </Tile>
      <Tile
        icon={<Boxes />}
        title={t("fwNftables")}
        tone={status.nft ? "ok" : "warn"}
        value={
          <Pill tone={status.nft ? "ok" : "warn"}>
            {t(status.nft ? "fwNftAvailable" : "fwNftMissing")}
          </Pill>
        }
      >
        {status.tables.length > 0 && (
          <Fact label={t("fwOtherTables")}>
            <span className="fw-chips">
              {status.tables.map((name) => (
                <bdi key={name} dir="ltr" className="fw-chip font-mono">
                  {name}
                </bdi>
              ))}
            </span>
          </Fact>
        )}
      </Tile>
      <Tile icon={<Network />} title={t("fwHost")} tone="muted" value={null}>
        <Fact label={t("fwUplink")}>
          {status.uplinks.length ? (
            <bdi dir="ltr" className="font-mono">
              {status.uplinks.join(", ")}
            </bdi>
          ) : (
            t("fwNoUplink")
          )}
        </Fact>
        <Fact label={t("fwSSH")}>
          <bdi dir="ltr" className="font-mono tabular-nums">
            {status.ssh.join(", ") || "—"}
          </bdi>
        </Fact>
        {status.docker && <Fact label={t("fwDocker")}>{t("fwPresent")}</Fact>}
        {status.firewalld && (
          <Fact label={t("fwFirewalldName")}>
            {t(
              status.firewalld === "active" ? "fwUFW_active" : "fwUFW_inactive",
            )}
          </Fact>
        )}
      </Tile>
    </div>
  );
}
