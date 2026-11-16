// Turns an operation's raw error into what happened and what to do next.
// The engine and broker messages stay the details; known causes get a
// translated explanation (eh_<key>, ehFix_<key>) and, where a page fixes
// it, a button. Unknown errors still show their own text. Unit-tested in
// tests/check.test.mjs.
import type { Page } from "./navigation";

export type ErrorHelp = {
  key: string;
  /** A page that fixes it, with its query. */
  page?: Page;
  params?: Record<string, string>;
  /** Reloading the list and trying again fixes it. */
  reload?: boolean;
};

const rules: [RegExp, ErrorHelp][] = [
  [
    /already uses the requested address\/port|Port is reserved by managed connection|Listener conflicts|address already in use/i,
    { key: "portInUse" },
  ],
  [
    /existing legacy forward already uses/i,
    { key: "legacyPort", page: "maintenance" },
  ],
  [/points back to its own listening port/i, { key: "loop" }],
  [
    /Connection changed; refresh|selection changed; refresh|no longer exists; reload|Server configuration changed|Firewall settings changed; reload|Configuration changed; review|revision; refresh/i,
    { key: "stale", reload: true },
  ],
  [
    /resolver reports global DNS|not readable by systemd-resolved|DNS on this server is managed by|Unknown resolver setup|DNS change failed/i,
    { key: "serverDNS", page: "optimize", params: { tab: "dns" } },
  ],
  [
    /Cannot resolve .* to an IPv|does not resolve to an IPv|has no resolved destination|No resolved destination/i,
    { key: "nameResolve" },
  ],
  [
    /Firewall settings were not fully applied|forward accept|FORWARD DROP|Forward accept reconciliation|UFW is not installed|in UFW\.|The firewall rules were rejected|Firewall change failed|Firewall recovery needs attention/i,
    { key: "firewall", page: "firewall" },
  ],
  [
    /Entrance IP is not assigned locally|Unknown local listener address/i,
    { key: "entranceIP" },
  ],
  [/Use the same IP version for all kernel targets/i, { key: "mixedFamily" }],
  [/IPv6 forwarding is disabled/i, { key: "ipv6Forwarding" }],
  [
    /Install the required tool first|needs? install|is not installed/i,
    { key: "missingTool", page: "components" },
  ],
  [
    /Preflight failed|configuration check failed|Invalid HAProxy values/i,
    { key: "preflight" },
  ],
  [
    /did not expose a new ready worker|Restart failed|Reload needs attention|failed to start|start request repeated/i,
    { key: "serviceStart" },
  ],
  [/Name already exists/i, { key: "nameTaken" }],
  [/MPTCP requires/i, { key: "mptcp" }],
  [
    /Use sudo|Run with sudo|Live operations require Linux|permission denied/i,
    { key: "privileges" },
  ],
  [
    /unauthori[sz]ed|session expired|csrf|\b401\b|\b403\b/i,
    { key: "session", reload: true },
  ],
  [
    /deadline exceeded|timed? ?out|context canceled|\b50[234]\b|Failed to fetch|NetworkError/i,
    { key: "unreachable" },
  ],
];

/** The engine's own sentences, without the broker's "operation failed: exit status N:" prefix. */
export function cleanError(text: string): string[] {
  const body = text
    .replace(/^operation failed:\s*/i, "")
    .replace(/^exit status \d+:\s*/i, "");
  const lines = body
    .split(/\n|(?=Error: )/)
    .map((line) => line.replace(/^Error:\s*/, "").trim())
    .filter(Boolean);
  return [...new Set(lines)];
}

export function explainError(text: string): ErrorHelp | undefined {
  return rules.find(([pattern]) => pattern.test(text))?.[1];
}

/** The message keys that explain an error: a known cause or the generic text. */
export function errorKeys(text: string) {
  const help = explainError(text);
  return help
    ? { title: `eh_${help.key}`, fix: `ehFix_${help.key}`, help }
    : { title: "ehUnknown", fix: "ehUnknownFix", help };
}
