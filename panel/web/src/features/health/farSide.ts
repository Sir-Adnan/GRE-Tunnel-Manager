// Framework-free: pairs local GRE tunnels with the checks Nodes run from
// the other end. Unit-tested in tests/features.test.mjs.
import type { Listing } from "@/features/nodes/types";

export type FarSideCheck = {
  node: string;
  ok: boolean;
  up: boolean;
  rtt_ms?: number;
  seen: string;
};

/**
 * A Node's tunnel belongs to a local one when it has the same GRE ID and
 * its remote end is one of this server's addresses.
 */
export function farSideChecks(
  listing: Listing | undefined,
  addresses: string[],
): Record<string, FarSideCheck> {
  const own = new Set(addresses);
  const out: Record<string, FarSideCheck> = {};
  for (const node of listing?.nodes ?? []) {
    if (node.local || !node.probes) continue;
    for (const t of node.probes.report.tunnels) {
      if (!own.has(t.remote)) continue;
      out[t.id] = { node: node.name, ok: t.ok, up: t.up, rtt_ms: t.rtt_ms, seen: node.probes.seen };
    }
  }
  return out;
}
