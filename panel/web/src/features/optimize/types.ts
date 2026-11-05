// Wire types for /api/optimize (see panel/internal/control/optimize.go).

export type OptimizeGroup = "conntrack" | "queues" | "relay" | "routing";

/** How far the values go: light touch, the default, or high-load sizes. */
export type OptimizeLevel = "conservative" | "balanced" | "aggressive";
/** What the server is mostly for. */
export type OptimizeGoal = "general" | "users" | "latency";

export type OptimizeProfile = { level: OptimizeLevel; goal: OptimizeGoal };

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
  /** Recommendation of the viewed profile; never worse than the original value. */
  recommended?: string;
  reason?: string;
  note?: Note;
};

/**
 * change: would improve; same: already the value; kept: the server's own
 * value is better; off: this profile leaves the key at its original value;
 * custom: a custom value; worse: a custom value worse than the original;
 * missing: not on this kernel.
 */
export type Note =
  "change" | "same" | "kept" | "off" | "custom" | "worse" | "missing";

export type OptimizeView = {
  memory: number;
  flows?: number;
  congestion: string[];
  steps: number;
  /** When the newest undo step was saved (Unix seconds). */
  last?: number;
  /** The profile applied last. */
  profile: OptimizeProfile;
  /** The profile the keys' recommendations belong to. */
  view: OptimizeProfile;
  /** Aggressive keeps balanced table and buffer sizes on a small server. */
  capped: boolean;
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
  /** Bounds for a custom value; absent when the key cannot be customized. */
  kind?: "number" | "triple" | "range" | "choice";
  min?: number;
  max?: number;
  choices?: string[];
};

export type OptimizePlan = {
  groups: OptimizeGroup[];
  profile: OptimizeProfile;
  changes: OptimizeChange[];
};
