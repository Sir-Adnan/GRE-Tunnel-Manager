import type { Inventory } from "@/lib/api";

export type Node = {
  id: string;
  name: string;
  revision: string;
  local: boolean;
  status: string;
  last_seen?: string;
  observed?: string;
  inventory_revision?: string;
  protocol: number;
  version?: string;
  capabilities: string[];
  inventory?: Inventory;
  failure?: { code: string; message: string };
  /** Far-side report of a v1.4.1+ Agent. */
  probes?: { seen: string; report: ProbeReport };
};
export type ProbeTunnel = {
  id: string;
  remote: string;
  local: string;
  address: string;
  peer: string;
  up: boolean;
  ok: boolean;
  rtt_ms?: number;
  error?: string;
};
export type ProbeReport = {
  time: string;
  host: {
    cpu_percent?: number;
    memory_total: number;
    memory_available: number;
    conntrack_count?: number;
    conntrack_max?: number;
  };
  tunnels: ProbeTunnel[];
};
export type SpeedTest = {
  id: string;
  node: string;
  tunnel: string;
  state: "waiting" | "connecting" | "running" | "done" | "failed";
  created: string;
  updated: string;
  upload_mbps?: number;
  download_mbps?: number;
  error?: string;
};
export type Listing = {
  enabled: boolean;
  url?: string;
  protocol: number;
  nodes: Node[];
};
export type Invitation = { code: string; expires: string };

export type NodeTrafficView = {
  node_id: string;
  status: string;
  observed?: string;
  summary?: {
    protocol: number;
    enabled: boolean;
    interval: number;
    since: string;
    failure?: string;
    counters: Record<
      string,
      {
        received: number;
        sent: number;
        cycle_received: number;
        cycle_sent: number;
        cycle_start: string;
        updated: string;
        source: string;
      }
    >;
  };
};
