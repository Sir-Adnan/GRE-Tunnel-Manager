// Port lists, kernel ranges and their mapping to remote ports. Mirrors
// model.ParsePortSpans and the Bash gtm_port_span contract; framework-free.

export const spanMax = 4096;
export type Span = { first: number; last: number };
export type PortMode = "" | "same" | "map";

export const spanLength = (s: Span) => s.last - s.first + 1;
export const spanText = (s: Span) =>
  s.first === s.last ? String(s.first) : `${s.first}-${s.last}`;

/** One "443" or "2000-2999"; undefined when invalid. */
export function parseSpan(word: string): Span | undefined {
  const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(word.trim());
  if (!m) return undefined;
  const first = Number(m[1]),
    last = m[2] === undefined ? first : Number(m[2]);
  if (first < 1 || last > 65535) return undefined;
  if (m[2] !== undefined && (last <= first || last - first >= spanMax))
    return undefined;
  return { first, last };
}

export type SpanError = "empty" | "invalid" | "overlap" | "tooMany" | "relayRange";

/**
 * Kernel engines keep each range as one span (one rule); relays expand to
 * single ports, at most 32 in total.
 */
export function parseSpans(
  value: string,
  kernel: boolean,
  /** Remote ports may repeat: several local ranges can go to one port. */
  repeat = false,
): { spans: Span[]; error?: SpanError } {
  const words = value.split(/[\s,]+/).filter(Boolean);
  if (!words.length) return { spans: [], error: "empty" };
  const spans: Span[] = [];
  for (const word of words) {
    const s = parseSpan(word);
    if (!s) return { spans, error: "invalid" };
    if (!kernel) {
      if (spanLength(s) > 32) return { spans, error: "relayRange" };
      for (let p = s.first; p <= s.last; p++)
        if (!spans.some((o) => o.first === p)) spans.push({ first: p, last: p });
    } else {
      if (!repeat && spans.some((o) => o.first <= s.last && s.first <= o.last))
        return { spans, error: "overlap" };
      spans.push(s);
    }
    if (spans.length > 32) return { spans, error: "tooMany" };
  }
  return { spans };
}

export const totalPorts = (spans: Span[]) =>
  spans.reduce((sum, s) => sum + spanLength(s), 0);

/**
 * The remote side of each local span for a mode: "same" keeps the numbers,
 * "map" reads remote (same count, each the same size or a single port), and
 * "" uses the target's own port. Returns an error key when map is invalid.
 */
export function remoteSpans(
  local: Span[],
  mode: PortMode,
  remote: string,
  targetPort: number,
): { spans: Span[]; error?: "mapCount" | "mapSize" | SpanError } {
  if (mode === "same") return { spans: local };
  if (mode === "map") {
    const parsed = parseSpans(remote, true, true);
    if (parsed.error) return { spans: [], error: parsed.error };
    if (parsed.spans.length !== local.length)
      return { spans: [], error: "mapCount" };
    if (
      parsed.spans.some(
        (s, i) => spanLength(s) !== 1 && spanLength(s) !== spanLength(local[i]),
      )
    )
      return { spans: [], error: "mapSize" };
    return { spans: parsed.spans };
  }
  return { spans: local.map(() => ({ first: targetPort, last: targetPort })) };
}

/** A few example pairs for the preview: "2000 → 3000", "… 2999 → 3999". */
export function mappingSamples(local: Span[], remote: Span[], limit = 4) {
  const out: { from: string; to: string }[] = [];
  local.forEach((s, i) => {
    const r = remote[i];
    if (!r) return;
    out.push({ from: spanText(s), to: spanText(r) });
  });
  return out.slice(0, limit);
}

/** True when PORT is inside a port list such as "2000-2999,8443". */
export function portIn(ports: string, port: number) {
  return ports
    .split(/[\s,]+/)
    .map(parseSpan)
    .some((s) => s && s.first <= port && port <= s.last);
}

/** Lowercase DNS name with a letter top-level label (the Bash gtm_hostname). */
export function isHostname(value: string) {
  return (
    value.length <= 253 &&
    /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/.test(
      value,
    )
  );
}

/** The record spelling of a target's port: "443" or "3000-3999". */
export const targetPorts = (t: { port: number; port_last?: number }) =>
  t.port_last && t.port_last > t.port ? `${t.port}-${t.port_last}` : String(t.port);

/** The first span of LENGTH ports after START that no listed port list uses. */
export function freeSpan(used: string[], start: number, length: number): Span | undefined {
  const taken: Span[] = used.flatMap((ports) => parseSpans(ports, true).spans);
  for (let first = start + 1; first + length - 1 <= 65535; first++) {
    const last = first + length - 1;
    const clash = taken.find((s) => s.first <= last && first <= s.last);
    if (!clash) return { first, last };
    first = clash.last;
  }
  return undefined;
}

/** A copy of a connection's ports moved to free ones (first port or range only). */
export function duplicatePorts(ports: string, used: string[]) {
  const first = parseSpans(ports, true).spans[0];
  if (!first) return "";
  const span = freeSpan(used, first.last, spanLength(first));
  return span ? spanText(span) : "";
}
