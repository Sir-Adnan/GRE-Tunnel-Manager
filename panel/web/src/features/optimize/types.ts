// Wire types for /api/optimize (see panel/internal/control/optimize.go).

export type OptimizeGroup = "conntrack" | "queues" | "relay" | "routing";

export type OptimizeKey = {
  group: OptimizeGroup | "previous";
  key: string;
  current: string;
  /** Value from before the panel first changed the key; absent when unmanaged. */
  before?: string;
  applied?: string;
  applied_group?: string;
  /** Another drop-in that sets the key too (the panel's file wins at boot). */
  other_file?: string;
  other_value?: string;
  /** Recommendation for this server; never worse than the live value. */
  recommended?: string;
  reason?: string;
  note?: Note;
};

/** change: would improve; same: already the recommendation; kept: the server's own value is better; missing: not on this kernel. */
export type Note = "change" | "same" | "kept" | "missing";

export type OptimizeView = {
  memory: number;
  flows?: number;
  congestion: string[];
  steps: number;
  file: string;
  import?: string;
  servertools: string[];
  keys: OptimizeKey[];
};

export type OptimizeChange = {
  group: OptimizeGroup;
  key: string;
  current?: string;
  value: string;
  reason: string;
  note: Note;
  other_file?: string;
  other_value?: string;
};

export type OptimizePlan = {
  groups: OptimizeGroup[];
  changes: OptimizeChange[];
};
