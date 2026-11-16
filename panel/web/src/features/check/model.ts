// Live packet path of one connection: rates between two samples of the
// owned rule counters (kernel forwards) or socket counts (relays), and a
// verdict that names where traffic stops. Framework-free; unit-tested in
// tests/check.test.mjs.

export type PathStageKey =
  "new" | "snat" | "out" | "back" | "blocked" | "clients" | "upstream";

export type PathStage = {
  key: PathStageKey;
  address?: string;
  packets: number;
  bytes: number;
};

export type ConnectionPath = {
  id: string;
  engine: string;
  enabled: boolean;
  time: string;
  stages: PathStage[];
  drops: string[];
};

/** A counter: its total since the rules were applied and, after a second sample, its rate per second. */
export type Flow = {
  total: number;
  bytes: number;
  rate?: number;
  byteRate?: number;
};

export type PathDestination = {
  address: string;
  out: Flow;
  back: Flow;
  /** Relays: connections open to this destination now. */
  upstream?: number;
};

export type Verdict =
  /** Saved disabled: no rules, nothing to measure. */
  | "disabled"
  /** An iptables backend drops the forwarded packets (owned accept missing). */
  | "dropped"
  /** Nothing has arrived (yet, or in the last interval). */
  | "idle"
  /** Packets arrive but none leave toward a destination. */
  | "stuck"
  /** Packets leave but no destination answers. */
  | "noAnswer"
  /** Some destinations answer, others do not. */
  | "partial"
  /** Traffic flows both ways. */
  | "flowing";

export type PathView = {
  kernel: boolean;
  /** Rates exist: the verdict describes the last interval, not the totals. */
  live: boolean;
  incoming: Flow;
  snat?: Flow;
  blocked?: Flow;
  /** Relays: TCP clients connected now. */
  clients?: number;
  destinations: PathDestination[];
  drops: string[];
  verdict: Verdict;
};

const kernelEngines = ["nftables", "iptables"];

function flow(
  stages: PathStage[],
  key: PathStageKey,
  address?: string,
): Flow | undefined {
  const matching = stages.filter(
    (s) => s.key === key && (address === undefined || s.address === address),
  );
  if (!matching.length) return undefined;
  return matching.reduce(
    (sum, s) => ({
      total: sum.total + s.packets,
      bytes: sum.bytes + s.bytes,
    }),
    { total: 0, bytes: 0 } as Flow,
  );
}

/** Adds rates from an earlier sample; a counter that went down was reset (rules reapplied). */
function withRate(now: Flow, before: Flow | undefined, seconds: number): Flow {
  if (!before || !(seconds > 0) || now.total < before.total) return now;
  return {
    ...now,
    rate: (now.total - before.total) / seconds,
    byteRate: Math.max(0, now.bytes - before.bytes) / seconds,
  };
}

const zero: Flow = { total: 0, bytes: 0 };

/** What moved: the rate once there are two samples, otherwise the total. */
export function activity(f?: Flow) {
  return f ? (f.rate ?? f.total) : 0;
}

/** Builds the view from the newest sample and, when it is the same connection, the one before. */
export function pathView(
  next: ConnectionPath,
  prev?: ConnectionPath,
): PathView {
  const kernel = kernelEngines.includes(next.engine);
  const comparable = prev && prev.id === next.id && prev.engine === next.engine;
  const seconds = comparable
    ? (Date.parse(next.time) - Date.parse(prev.time)) / 1000
    : 0;
  const rated = (key: PathStageKey, address?: string) => {
    const now = flow(next.stages, key, address);
    if (!now) return undefined;
    return withRate(
      now,
      comparable ? flow(prev.stages, key, address) : undefined,
      seconds,
    );
  };
  const addresses = [
    ...new Set(
      next.stages
        .filter((s) => s.address && ["out", "back", "upstream"].includes(s.key))
        .map((s) => s.address as string),
    ),
  ];
  const destinations: PathDestination[] = addresses.map((address) =>
    kernel
      ? {
          address,
          out: rated("out", address) ?? zero,
          back: rated("back", address) ?? zero,
        }
      : {
          address,
          out: zero,
          back: zero,
          upstream: flow(next.stages, "upstream", address)?.total ?? 0,
        },
  );
  const clients = kernel ? undefined : flow(next.stages, "clients")?.total;
  const view: PathView = {
    kernel,
    live: Boolean(comparable && seconds > 0),
    incoming: kernel
      ? (rated("new") ?? zero)
      : { total: clients ?? 0, bytes: 0 },
    snat: rated("snat"),
    blocked: rated("blocked"),
    clients,
    destinations,
    drops: next.drops,
    verdict: "idle",
  };
  view.verdict = verdict(view, next.enabled);
  return view;
}

export function verdict(view: PathView, enabled: boolean): Verdict {
  if (!enabled) return "disabled";
  if (view.kernel && view.drops.length) return "dropped";
  if (!view.kernel) {
    const open = view.destinations.map((d) => d.upstream ?? 0);
    if (!view.clients && !open.some(Boolean)) return "idle";
    if (open.length && !open.some(Boolean)) return "noAnswer";
    return "flowing";
  }
  const sent = view.destinations.map((d) => activity(d.out));
  const answered = view.destinations.map((d) => activity(d.back));
  if (!activity(view.incoming) && !sent.some(Boolean)) return "idle";
  if (!sent.some(Boolean)) return "stuck";
  if (!answered.some(Boolean)) return "noAnswer";
  if (sent.some((s, i) => s > 0 && !answered[i])) return "partial";
  return "flowing";
}

/** Destinations that were sent traffic but never answered (for the "partial" verdict). */
export function silentDestinations(view: PathView) {
  return view.destinations
    .filter((d) => activity(d.out) > 0 && !activity(d.back))
    .map((d) => d.address);
}

/** The connection a create added: the newest ID that was not there before. */
export function createdConnection(
  known: string[],
  connections: { id: string }[],
): string | undefined {
  const before = new Set(known);
  return connections
    .map((c) => c.id)
    .filter((id) => !before.has(id))
    .sort()
    .at(-1);
}
