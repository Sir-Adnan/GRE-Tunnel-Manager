/** Mirrors auth.SessionInfo and the /api/security view. */
export type SessionInfo = {
  id: string;
  created: string;
  last_seen: string;
  expires: string;
  address: string;
  agent: string;
  current: boolean;
};
export type SecurityView = {
  two_factor: boolean;
  recovery_remaining: number;
  sessions: SessionInfo[];
};
export type TwoFactorSetup = { secret: string; uri: string; qr: string[] };

/** A short "Browser · OS" name from a User-Agent; never shows the raw string. */
export function describeAgent(agent: string): { browser: string; os: string } {
  const browser = /Edg(e|A|iOS)?\//.test(agent)
    ? "Edge"
    : /OPR\/|Opera/.test(agent)
      ? "Opera"
      : /Firefox\/|FxiOS\//.test(agent)
        ? "Firefox"
        : /Chrome\/|CriOS\//.test(agent)
          ? "Chrome"
          : /Safari\//.test(agent)
            ? "Safari"
            : /curl\//.test(agent)
              ? "curl"
              : "";
  const os = /Windows/.test(agent)
    ? "Windows"
    : /iPhone|iPad|iPod/.test(agent)
      ? "iOS"
      : /Android/.test(agent)
        ? "Android"
        : /Mac OS X|Macintosh/.test(agent)
          ? "macOS"
          : /CrOS/.test(agent)
            ? "ChromeOS"
            : /Linux/.test(agent)
              ? "Linux"
              : "";
  return { browser, os };
}

/** The QR modules as one SVG path, with the standard four-module margin. */
export function qrPath(rows: string[]): { size: number; d: string } {
  let d = "";
  rows.forEach((row, y) => {
    for (let x = 0; x < row.length; x++)
      if (row[x] === "1") d += `M${x + 4} ${y + 4}h1v1h-1z`;
  });
  return { size: rows.length + 8, d };
}

/** Groups the secret in fours so it can be typed into an app by hand. */
export const groupSecret = (secret: string) =>
  secret.replace(/(.{4})/g, "$1 ").trim();

export const sixDigits = (value: string) => /^\d{6}$/.test(value.trim());
