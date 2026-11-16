// Per connection: how traffic reaches it (FORWARD for kernel forwards,
// INPUT for relays), its UFW opening and who may use it.
import { Layers3, Pencil, ShieldBan } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import { HelpTip } from "@/components/help";
import { EngineGlyph } from "@/components/shared";
import { useT } from "@/lib/i18n";
import {
  accessOf,
  blockedFor,
  familyOf,
  kernelEngine,
  type FirewallConnection,
  type FirewallSettings,
  type FirewallStatus,
} from "./model";
import { Pill, PortText } from "./parts";
import { fill, useNumber } from "./text";

export function ConnectionRules({
  connections,
  status,
  settings,
  busy,
  edit,
  focus,
  setUFW,
}: {
  connections: FirewallConnection[];
  status: FirewallStatus;
  settings: FirewallSettings;
  busy: boolean;
  edit: (id: string) => void;
  /** The connection a link pointed at: highlighted. */
  focus?: string;
  setUFW: (id: string, open: boolean) => void;
}) {
  const t = useT();
  const format = useNumber();
  return (
    <section className="fw-section" aria-labelledby="fw-connections">
      <div className="fw-section-head">
        <h2 id="fw-connections" className="fw-section-title">
          {t("fwConnections")}
        </h2>
        <HelpTip label={`${t("fwConnections")} · ?`}>
          {t("fwConnectionsHelp")}
        </HelpTip>
      </div>
      {connections.length === 0 ? (
        <Empty className="min-h-48 rounded-xl border bg-card">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <Layers3 />
            </EmptyMedia>
            <EmptyTitle>{t("fwNoConnections")}</EmptyTitle>
            <EmptyDescription>{t("fwNoConnectionsBody")}</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <ul className="fw-conn-list">
          {connections.map((c) => {
            const kernel = kernelEngine(c.engine);
            const ports = status.ports.filter((p) => p.id === c.id);
            const access = accessOf(settings, c.id);
            const blocked = blockedFor(status, c.id);
            const family = familyOf(c.bind);
            const guardMissing =
              kernel &&
              status.backends.some(
                (b) => b.family === family && b.forward === "DROP" && !b.guard,
              );
            const open = settings.ufw.includes(c.id);
            const switchID = `fw-ufw-${c.id}`;
            return (
              <li
                key={c.id}
                id={`fw-${c.id}`}
                className="fw-conn"
                data-enabled={c.enabled}
                data-focus={c.id === focus || undefined}
              >
                <div className="fw-conn-main">
                  <div className="fw-conn-title">
                    <EngineGlyph
                      engine={c.engine}
                      className="size-4 shrink-0 text-muted-foreground"
                    />
                    <bdi className="truncate font-medium">{c.name || c.id}</bdi>
                    {!c.enabled && (
                      <Badge variant="outline">{t("fwDisabled")}</Badge>
                    )}
                  </div>
                  <p className="fw-conn-path">
                    {t(kernel ? "fwKernelPath" : "fwRelayPath")}
                  </p>
                  <div className="fw-chips">
                    {ports.map((p) => (
                      <span key={`${p.protocol}-${p.port}`} className="fw-port">
                        <PortText port={p.port} protocol={p.protocol} />
                        {!kernel && p.ufw && (
                          <Pill
                            tone={
                              p.ufw === "closed"
                                ? status.ufw.state === "active"
                                  ? "warn"
                                  : "muted"
                                : "ok"
                            }
                          >
                            {t(`fwPortState_${p.ufw}`)}
                          </Pill>
                        )}
                      </span>
                    ))}
                    {kernel && (
                      <Pill tone={guardMissing ? "problem" : "ok"}>
                        {t("fwForward")} ·{" "}
                        {t(guardMissing ? "fwGuardOff" : "fwGuardOn")}
                      </Pill>
                    )}
                  </div>
                </div>
                <div className="fw-conn-access">
                  <span className="fw-access-summary">
                    <span className="text-xs text-muted-foreground">
                      {t("fwAccess")}
                    </span>
                    <span className="text-sm font-medium">
                      {access.mode === "off"
                        ? t("fwAccessEveryone")
                        : fill(
                            t(
                              access.mode === "allow"
                                ? "fwAccessAllow"
                                : "fwAccessDeny",
                            ),
                            {
                              n: format(access.sources.length),
                            },
                          )}
                    </span>
                    <span className="fw-chips">
                      {access.per_ip > 0 && (
                        <span className="fw-chip">
                          {fill(t("fwLimitPerIP"), {
                            n: format(access.per_ip),
                          })}
                        </span>
                      )}
                      {access.rate > 0 && (
                        <span className="fw-chip">
                          {fill(t("fwLimitRate"), { n: format(access.rate) })}
                        </span>
                      )}
                      {blocked > 0 && (
                        <span className="fw-chip" data-tone="problem">
                          <ShieldBan className="size-3" aria-hidden />
                          {fill(t("fwBlocked"), { n: format(blocked) })}
                        </span>
                      )}
                    </span>
                  </span>
                  <div className="fw-conn-actions">
                    {!kernel && (
                      <span className="fw-switch">
                        <Switch
                          id={switchID}
                          checked={open}
                          aria-label={`${t("fwOpenInUFW")}: ${c.name || c.id}`}
                          disabled={busy || status.ufw.state === "missing"}
                          onCheckedChange={(value) => setUFW(c.id, value)}
                        />
                        <label
                          htmlFor={switchID}
                          className="cursor-pointer text-sm"
                        >
                          {t("fwOpenInUFW")}
                        </label>
                        <HelpTip label={`${t("fwOpenInUFW")} · ?`}>
                          {t("fwOpenInUFWHelp")}
                        </HelpTip>
                      </span>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() => edit(c.id)}
                      aria-label={`${t("fwEditAccess")}: ${c.name || c.id}`}
                    >
                      <Pencil data-icon="inline-start" />
                      {t("fwEditAccess")}
                    </Button>
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
