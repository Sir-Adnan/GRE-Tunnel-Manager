// Badges on a connection card: the source address the destination sees and
// what the firewall does with the connection. Framework-free; unit-tested
// in tests/check.test.mjs.
import {
  accessOf,
  familyOf,
  kernelEngine,
  type FirewallStatus,
} from "../firewall/model.ts";

/** Fired after a firewall change made outside the Firewall page. */
export const firewallChanged = "gtm:firewall-changed";

export type ConnectionBadge = {
  key:
    | "cbSourceServer"
    | "cbSourceClient"
    | "cbForwardBlocked"
    | "cbUFWClosed"
    | "cbAllow"
    | "cbDeny"
    | "cbLimited";
  tone?: "warn" | "problem";
  /** A count shown after the label (allow and block list sizes). */
  count?: number;
  /** The badge opens the Firewall page. */
  firewall?: boolean;
};

type Row = {
  id: string;
  engine: string;
  bind: string;
  snat: string;
  enabled: boolean;
};

export function connectionBadges(
  row: Row,
  status?: FirewallStatus,
): ConnectionBadge[] {
  const kernel = kernelEngine(row.engine);
  const out: ConnectionBadge[] = [];
  if (kernel)
    out.push({
      key: row.snat === "masquerade" ? "cbSourceServer" : "cbSourceClient",
    });
  if (!status) return out;
  if (row.enabled && kernel) {
    const family = familyOf(row.bind);
    if (
      status.backends.some(
        (b) => b.family === family && b.forward === "DROP" && !b.guard,
      )
    )
      out.push({ key: "cbForwardBlocked", tone: "problem", firewall: true });
  }
  if (
    row.enabled &&
    !kernel &&
    status.ufw.state === "active" &&
    status.ports.some((p) => p.id === row.id && p.ufw === "closed")
  )
    out.push({ key: "cbUFWClosed", tone: "warn", firewall: true });
  const access = accessOf(status.settings, row.id);
  if (access.mode === "allow")
    out.push({ key: "cbAllow", count: access.sources.length, firewall: true });
  else if (access.mode === "deny")
    out.push({ key: "cbDeny", count: access.sources.length, firewall: true });
  else if (access.per_ip > 0 || access.rate > 0)
    out.push({ key: "cbLimited", firewall: true });
  return out;
}
