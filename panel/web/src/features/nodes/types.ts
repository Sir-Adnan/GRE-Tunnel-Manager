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
