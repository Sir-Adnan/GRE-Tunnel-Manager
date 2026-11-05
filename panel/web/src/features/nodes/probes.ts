// Framework-free helpers for Node probe reports.
import type { ProbeTunnel } from "./types";

/** "2 of 3 tunnels answer from this side". */
export function tunnelSummary(tunnels: ProbeTunnel[]) {
  return { ok: tunnels.filter((x) => x.ok).length, total: tunnels.length };
}
