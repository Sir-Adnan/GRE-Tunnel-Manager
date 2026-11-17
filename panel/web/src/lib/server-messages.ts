// Translates the panel's own server answers (HTTP API, sign-in, broker panel
// actions) into the interface language. The server keeps one English sentence
// per answer; this catalogue maps each one to a message key (srv_*). Unknown
// text, such as an engine's own report, is shown unchanged.
//
// tests/server-messages.test.mjs checks that every exact entry still occurs in
// the Go sources, so renaming a server sentence fails the tests instead of
// silently falling back to English.

/** Exact server sentences and the key that translates them. */
export const exactMessages: Record<string, string> = {
  // HTTP layer
  "not found": "srvNotFound",
  "Node not found": "srvNodeNotFound",
  "job not found": "srvJobNotFound",
  "panel busy": "srvBusy",
  "method not allowed": "srvInvalidRequest",
  "use application/json": "srvInvalidRequest",
  "use POST": "srvInvalidRequest",
  "invalid request": "srvInvalidRequest",
  "one request required": "srvInvalidRequest",
  "unknown operation": "srvInvalidRequest",
  "invalid broker answer": "srvBroker",
  "metrics unavailable": "srvMetrics",
  unauthorized: "srvSignIn",
  "sign in to continue": "srvSignIn",
  "same-origin request required": "srvSecurityCheck",
  "invalid CSRF token": "srvSecurityCheck",
  "another operation is running; wait for it to finish": "srvOperationRunning",
  // Sign-in
  "incorrect username or password": "srvCredentials",
  "invalid credentials": "srvCredentials",
  "too many login attempts; try again in 5 minutes": "srvThrottled",
  "too many active sessions": "srvTooManySessions",
  "enter the code from your authenticator app": "srvCodeRequired",
  "incorrect code": "srvIncorrectCode",
  "incorrect password": "srvIncorrectPassword",
  "incorrect password or code": "srvIncorrectPasswordOrCode",
  "choose a password different from the current one": "srvPasswordSame",
  "too many wrong passwords; try again in 10 minutes": "srvPasswordThrottled",
  "password must contain at least 8 characters and at most 72 UTF-8 bytes":
    "passwordTooShort",
  "the password was saved but the panel could not apply it; restart the panel":
    "srvPasswordRestart",
  // Two-factor and sessions
  "two-factor sign-in is already on": "srvTwoFactorOn",
  "two-factor sign-in is already on; turn it off first": "srvTwoFactorOn",
  "the setup expired; start again": "srvSetupExpired",
  "the code does not match; check the time on your phone and try the next code":
    "srvCodeMismatch",
  "invalid two-factor secret": "srvSetupExpired",
  "could not draw the QR code": "srvSetupFailed",
  "could not create a secret": "srvSetupFailed",
  "that session has already ended": "srvSessionEnded",
  "choose one session or all other sessions": "srvInvalidRequest",
  "another recovery request is running; wait for it to finish":
    "srvOperationRunning",
  // Certificates
  "enter a public IP address or a domain name": "tlsHostInvalid",
  "Let's Encrypt certifies public addresses only": "tlsHostPrivate",
  "enter a valid email address or leave it empty": "srvEmail",
  "certificate reload is available on the HTTPS panel only": "srvReloadHTTPS",
  "certificate reload failed; the previous certificate remains loaded; check the certificate files and public host":
    "srvReloadFailed",
  // Updates
  "update checks are unavailable": "srvUpdateUnavailable",
  "an update is already running": "srvUpdateRunning",
  "no newer release is known; check for updates first": "srvUpdateNone",
};

/** Server sentences with a variable tail: the key, and the tail as {e}. */
const prefixMessages: [string, string][] = [
  ["could not reach the release server: ", "srvReleaseServer"],
  ["the update could not start: ", "srvUpdateStart"],
];

export type ServerMessage = { key: string; detail?: string };

/** The message key for a server sentence, or undefined when it is not one of the panel's own. */
export function serverMessage(text: string): ServerMessage | undefined {
  const body = text.replace(/^operation failed:\s*/i, "").trim();
  const exact = exactMessages[body];
  if (exact) return { key: exact };
  for (const [prefix, key] of prefixMessages)
    if (body.startsWith(prefix))
      return { key, detail: body.slice(prefix.length) };
  if (/^HTTP 5\d\d$/.test(body) || body === "Invalid server response")
    return { key: "srvUnreachable" };
  if (/^HTTP 4(01|03)$/.test(body)) return { key: "srvSignIn" };
  if (/^(Failed to fetch|NetworkError|Load failed)/i.test(body))
    return { key: "srvUnreachable" };
  return undefined;
}

/** The text of any thrown value, translated when the panel knows it. */
export function errorText(
  error: unknown,
  translate: (key: string) => string,
): string {
  const text =
    error instanceof Error ? error.message : String(error ?? "").trim();
  const known = serverMessage(text);
  if (!known) return text;
  const message = translate(known.key);
  return known.detail === undefined
    ? message
    : message.replace("{e}", known.detail);
}
