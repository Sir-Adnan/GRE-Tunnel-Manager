// One visual state per connection for its status chip and route chain. Framework-free; unit-tested in
// tests/connection-tone.test.mjs. It summarizes facts the list already has (service state, health checks and
// firewall badges) and never claims traffic flows: "ok" means nothing known stops it.

export type Tone = "ok" | "warn" | "problem" | "off" | "pending";

type Row = { status?: string; enabled: boolean };
type Health = "up" | "degraded" | "down" | "unknown" | "off" | undefined;
type Badge = { tone?: "warn" | "problem" };

const pending = new Set(["activating", "deactivating", "reloading"]);

export function connectionTone(
  row: Row,
  health?: Health,
  badges: readonly Badge[] = [],
): Tone {
  if (!row.enabled || row.status === "disabled") return "off";
  if (
    row.status === "failed" ||
    row.status === "inactive" ||
    health === "down" ||
    badges.some((b) => b.tone === "problem")
  )
    return "problem";
  if (row.status && pending.has(row.status)) return "pending";
  if (health === "degraded" || badges.some((b) => b.tone === "warn"))
    return "warn";
  // Kernel forwards report "configured" (rules loaded, no service); relays report "active".
  if (row.status === "active" || row.status === "configured") return "ok";
  return "pending";
}

/** Message key that names a tone for screen readers and tooltips. */
export const toneLabel: Record<Tone, string> = {
  ok: "toneOk",
  warn: "toneWarn",
  problem: "toneProblem",
  off: "toneOff",
  pending: "tonePending",
};
