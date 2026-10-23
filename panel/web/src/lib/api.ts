export type Target = { ip: string; port: number; weight: number };
export type Connection = {
  id: string;
  name: string;
  engine: string;
  protocol: string;
  bind: string;
  ports: string;
  strategy: string;
  enabled: boolean;
  snat: string;
  interface: string;
  targets: Target[];
  options: Record<string, string>;
  revision: string;
  status?: string;
};
export type Resource = {
  id: string;
  engine: string;
  name: string;
  role: string;
  status: string;
  interface?: string;
  description: string;
  configured: boolean;
  port?: number;
  bind?: string;
  protocol?: string;
};
export type Option = {
  key: string;
  min?: number;
  max?: number;
  default: string;
  choices?: string[];
  format?: string;
};
export type Component = {
  id: string;
  installed: boolean;
  version?: string;
  peer_version?: string;
  compatibility?: string;
};
export type EngineProfile = {
  id: string;
  version_policy: string;
  validation: string;
  features: string[];
  limitations: string[];
};
export type Capability = {
  id: string;
  protocols: string[];
  strategies: string[];
  options: Option[];
  scope: string;
};
export type Inventory = {
  connections: Connection[];
  resources: Resource[];
  components: Component[];
  engine_profiles?: EngineProfile[];
  capabilities: Capability[];
  host: {
    hostname: string;
    os: string;
    addresses: string[];
    uptime: string;
    memory_total: number;
    memory_available: number;
    load: string;
    public_ip?: string;
  };
  version: string;
  demo: boolean;
};
export type Session = {
  authenticated: boolean;
  session: { csrf: string; username: string; expires: string };
  demo: boolean;
};
export type Job = {
  id: string;
  action: string;
  state: string;
  result?: unknown;
  error?: string;
};
export type Metrics = {
  settings: { enabled: boolean; interval: number; ids: string[] };
  counters: Record<
    string,
    { received: number; sent: number; updated: string; source: string }
  >;
  since: string;
  error?: string;
};
let csrf = "";
export async function api<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(`/api/${path}`, {
    credentials: "same-origin",
    headers:
      body === undefined
        ? {}
        : { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    ...(body === undefined
      ? {}
      : { method: "POST", body: JSON.stringify(body) }),
  });
  const value = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path !== "login")
      window.dispatchEvent(new Event("gtm:unauthorized"));
    throw new Error(value.error || `HTTP ${response.status}`);
  }
  if (value.session?.csrf) csrf = value.session.csrf;
  return value as T;
}
export async function operate(
  request: unknown,
  changed?: (job: Job) => void,
): Promise<Job> {
  let job = await api<Job>("operations", request);
  changed?.(job);
  while (job.state === "running") {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    job = await api<Job>(`jobs/${job.id}`);
    changed?.(job);
  }
  if (job.state === "failed") throw new Error(job.error || "Operation failed");
  return job;
}
export function bytes(value: number): string {
  if (!value) return "0 B";
  const unit = Math.min(Math.floor(Math.log(value) / Math.log(1024)), 4);
  return `${(value / 1024 ** unit).toLocaleString("en", { maximumFractionDigits: 1 })} ${["B", "KiB", "MiB", "GiB", "TiB"][unit]}`;
}
export function endpoint(ip: string, port: number | string): string {
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}
