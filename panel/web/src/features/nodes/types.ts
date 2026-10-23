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
