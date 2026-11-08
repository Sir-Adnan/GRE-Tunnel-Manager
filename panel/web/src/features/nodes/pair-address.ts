/** The host fields a pairing default needs. */
export interface PairHost {
  public_ip?: string;
  addresses?: string[];
}

/**
 * Default address of one side of a pair. The saved public IP comes from the
 * panel's installation; after an IP change it is no longer on the server, and
 * a GRE source must be a local address. A still-assigned public IP wins, then
 * the first IPv4 address (the server lists its uplink first), then any.
 */
export function pairAddress(host?: PairHost): string {
  const local = host?.addresses ?? [];
  if (host?.public_ip && local.includes(host.public_ip)) return host.public_ip;
  return (
    local.find((ip) => !ip.includes(":")) || local[0] || host?.public_ip || ""
  );
}
