export type AccessView = {
  protocol: "http" | "https";
  host?: string;
  issuer?: string;
  not_after?: string;
  fingerprint?: string;
  self_signed: boolean;
  trusted: boolean;
  hostname_ok: boolean;
  loaded?: string;
  last_error?: string;
};

export function certificateState(value: AccessView | undefined, now: number) {
  if (!value || value.protocol === "http") return "http";
  const remaining = Date.parse(value.not_after || "") - now;
  if (!Number.isFinite(remaining) || remaining <= 0) return "expired";
  if (remaining <= 7 * 86400000) return "expiring";
  if (value.self_signed) return "selfSigned";
  return value.trusted && value.hostname_ok ? "valid" : "privateCA";
}
