export type RenewalView = {
  source: "letsencrypt" | "acme" | "external" | "self-signed";
  host?: string;
  challenge?: string;
  profile?: string;
  staging?: boolean;
  auto_renew: boolean;
  renew_after?: string;
  last_attempt?: string;
  last_error?: string;
};

export type AccessView = {
  protocol: "http" | "https";
  host?: string;
  issuer?: string;
  not_before?: string;
  not_after?: string;
  fingerprint?: string;
  self_signed: boolean;
  trusted: boolean;
  hostname_ok: boolean;
  loaded?: string;
  last_error?: string;
  renewal?: RenewalView;
};

const day = 86400000;

/** Warn when renewal is overdue. Panel-renewed certificates warn once half of
 * their renewal window has passed, so six-day IP certificates are not always
 * "expiring"; other certificates warn in their last seven days. */
export function certificateState(value: AccessView | undefined, now: number) {
  if (!value || value.protocol === "http") return "http";
  const end = Date.parse(value.not_after || "");
  const remaining = end - now;
  if (!Number.isFinite(remaining) || remaining <= 0) return "expired";
  const start = Date.parse(value.not_before || "");
  const warning =
    value.renewal?.auto_renew && Number.isFinite(start)
      ? (end - start) / 6
      : 7 * day;
  if (remaining <= warning) return "expiring";
  if (value.self_signed) return "selfSigned";
  return value.trusted && value.hostname_ok ? "valid" : "privateCA";
}

/** Where the loaded certificate comes from; drives the help text and the
 * renewal row. Older panels without a record fall back to the certificate. */
export function certificateSource(value: AccessView | undefined) {
  if (!value || value.protocol === "http") return "http";
  const source = value.renewal?.source;
  if (source === "letsencrypt" || source === "acme")
    return value.renewal?.auto_renew ? "managed" : "external";
  if (source === "external") return "external";
  return value.self_signed ? "selfSigned" : "external";
}

const domain =
  /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

/** A domain or IP address Let's Encrypt can certify. Private, loopback and
 * unspecified addresses are refused here and again on the server. */
export function certificateHostError(value: string): string {
  const host = value.trim().toLowerCase();
  if (!host) return "";
  if (ipv4.test(host)) {
    const [a, b] = host.split(".").map(Number);
    const local =
      a === 10 ||
      a === 127 ||
      a === 0 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168);
    return local ? "tlsHostPrivate" : "";
  }
  if (host.includes(":")) {
    if (!/^[0-9a-f:.]+$/.test(host)) return "tlsHostInvalid";
    return /^(::1?|fe[89ab][0-9a-f]?:|f[cd][0-9a-f]{2}:)/.test(host)
      ? "tlsHostPrivate"
      : "";
  }
  return domain.test(host) ? "" : "tlsHostInvalid";
}

/** Where the panel answers after an HTTP panel switches to HTTPS. */
export function httpsAddress(
  host: string,
  location: { hostname: string; port: string },
) {
  const name = host.trim().toLowerCase() || location.hostname;
  const bracketed =
    name.includes(":") && !name.startsWith("[") ? `[${name}]` : name;
  return `https://${bracketed}${location.port ? `:${location.port}` : ""}/`;
}

const email = /^[^\s@<>()",;:\\]{1,64}@[a-z0-9.-]{1,190}\.[a-z]{2,24}$/i;
export const emailValid = (value: string) =>
  !value.trim() || email.test(value.trim());
