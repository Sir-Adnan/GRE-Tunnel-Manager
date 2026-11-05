// Wire types for /api/health and /api/maintenance (see panel/internal/health and maintenance).

export type HealthStatus = "up" | "degraded" | "down" | "unknown";

export type HealthSettings = {
  enabled: boolean;
  interval: number;
  fail_threshold: number;
  recover_threshold: number;
  latency_warn_ms: number;
  retention_days: number;
  /** Kernel forwards whose dead destinations stop getting new flows. */
  failover: string[];
  failover_interval: number;
};

export type HealthPoint = { t: number; r: number };

export type HealthTarget = {
  key: string;
  owner: string;
  name: string;
  engine: string;
  kind: "tcp" | "icmp" | "service";
  address?: string;
  port?: number;
  unit?: string;
  status: HealthStatus;
  since: string;
  checked?: string;
  rtt_ms?: number;
  error?: string;
  recent: HealthPoint[];
  uptime_24h: number | null;
  /** Share of failed checks in 24 h (packet loss for pings). */
  loss_24h?: number;
  /** "haproxy" when the relay's own health check supplied the result. */
  via?: string;
  sessions?: number;
  backup?: boolean;
};

export type HealthOwner = {
  owner: string;
  name: string;
  engine: string;
  status: HealthStatus;
  since: string;
  latency_ms?: number;
  uptime_24h: number | null;
  uptime_7d: number | null;
  uptime_30d: number | null;
  hours: (number | null)[];
  days: (number | null)[];
  targets: HealthTarget[];
};

export type Outage = {
  id: number;
  key: string;
  owner: string;
  name: string;
  engine: string;
  endpoint: string;
  start: string;
  end?: string;
  reason?: string;
};

export type HostPressure = {
  time: string;
  conntrack_count?: number;
  conntrack_max?: number;
  conntrack_percent?: number;
  conntrack_buckets?: number;
  tcp_established_timeout?: number;
  drops: number;
  early_drops: number;
  insert_failed: number;
  cpu_percent?: number;
  steal_percent?: number;
  softirq_percent?: number;
  iowait_percent?: number;
  conntrack_cli: boolean;
  hints: string[];
};

export type HealthView = {
  settings: HealthSettings;
  revision: number;
  time: string;
  timezone: string;
  summary: {
    owners: number;
    up: number;
    degraded: number;
    down: number;
    unknown: number;
    open_outages: number;
    uptime_24h: number | null;
    uptime_7d: number | null;
    latency_ms?: number;
  };
  owners: HealthOwner[];
  outages: Outage[];
  host?: HostPressure;
  failover: Record<string, FailoverStatus>;
};

export type FailoverStatus = {
  /** 1-based destination positions that receive no new flows. */
  excluded: number[];
  changed?: string;
  message?: string;
  error?: string;
};

/** New connections per destination since the forward's rules were applied. */
export type FlowCounts = {
  owner: string;
  total: number;
  destinations: number[];
  time: string;
};

export type MTUResult = {
  address: string;
  interface_mtu: number;
  path_mtu: number;
  probes: number;
  failed?: number[];
  duration_ms: number;
};

export type ReportRow = {
  owner: string;
  name: string;
  engine: string;
  checks: number;
  uptime: number | null;
  outages: number;
  downtime_seconds: number;
  latency_ms?: number;
  latency_max_ms?: number;
  jitter_ms?: number;
  removed?: boolean;
};

export type HealthReport = {
  start: string;
  end: string;
  offset: number;
  weeks: number;
  complete: boolean;
  generated: string;
  timezone: string;
  rows: ReportRow[];
  uptime: number | null;
  outages: number;
  downtime_seconds: number;
  longest?: Outage;
  host: {
    cpu_percent?: number;
    steal_percent?: number;
    softirq_percent?: number;
    conntrack_peak_percent?: number;
    drops: number;
  };
  maintenance: MaintenanceEntry[];
  traffic: Record<string, { received: number; sent: number }>;
};

export type Action = "refresh" | "restart" | "reboot";
export type TriggerKind = "interval" | "daily" | "weekly" | "uptime" | "health";

export type Trigger = {
  kind: TriggerKind;
  hours?: number;
  times?: string[];
  days?: number[];
  uptime_days?: number;
  condition?: "down" | "latency";
  minutes?: number;
  latency_ms?: number;
};

export type Guards = {
  window?: string;
  quiet_mbps?: number;
  quiet_wait?: number;
  quiet_timeout?: "run" | "skip" | "";
  cooldown: number;
  max_per_day: number;
  min_uptime?: number;
  notice?: number;
  stagger?: number;
};

export type Plan = {
  id: string;
  name: string;
  enabled: boolean;
  action: Action;
  scope: string[];
  trigger: Trigger;
  guards: Guards;
  dry_run: boolean;
  created?: string;
};

export type Pending = {
  reason: string;
  detail?: string;
  owners: string[];
  since: string;
  run_at: string;
  deadline?: string;
  manual?: boolean;
};

export type PlanView = Plan & {
  state: {
    next?: string;
    last?: string;
    last_result?: string;
    runs_today: number;
    pending?: Pending;
    note?: string;
  };
};

export type MaintenanceEntry = {
  id: number;
  plan: string;
  plan_name: string;
  action: Action;
  owner?: string;
  owner_name?: string;
  engine?: string;
  reason: string;
  started: string;
  ended: string;
  result: "ok" | "failed" | "skipped" | "dry-run" | "cancelled" | "rebooting";
  message?: string;
};

export type MaintenanceView = {
  settings: { enabled: boolean; timezone: string };
  revision: number;
  time: string;
  plans: PlanView[];
  history: MaintenanceEntry[];
  uptime_seconds: number;
  health_enabled: boolean;
  conntrack_cli: boolean;
};

/** One connection or resource a plan can act on. */
export type Owner = { id: string; name: string; engine: string };
