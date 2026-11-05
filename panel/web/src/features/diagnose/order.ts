// Framework-free diagnosis helpers; unit-tested in tests/features.test.mjs.
export type DiagnoseCheck = {
  key: string;
  status: "ok" | "warn" | "fail" | "info";
  detail?: string;
  rtt_ms?: number;
};

export type DiagnoseReport = {
  owner: string;
  time: string;
  status: "ok" | "warn" | "fail";
  checks: DiagnoseCheck[];
  outage?: { start: string; end?: string; reason?: string; endpoint: string };
};

/** Problems first, then the rest in the order the checks ran. */
export function orderChecks(checks: DiagnoseCheck[]): DiagnoseCheck[] {
  const rank = { fail: 0, warn: 1, info: 2, ok: 3 } as const;
  return checks
    .map((c, i) => ({ c, i }))
    .sort((a, b) => rank[a.c.status] - rank[b.c.status] || a.i - b.i)
    .map(({ c }) => c);
}

