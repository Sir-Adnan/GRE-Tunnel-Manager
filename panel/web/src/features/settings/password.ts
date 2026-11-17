// Client checks for a new panel password. They mirror the server's rule
// (config.ValidatePassword: 8+ characters, at most 72 UTF-8 bytes, no control
// characters); the broker still decides.

export type PasswordIssue = {
  field: "next" | "repeat";
  key: "passwordTooShort" | "passwordMismatch" | "srvPasswordSame";
};

const control = /\p{Cc}/u;

export function passwordIssue(
  current: string,
  next: string,
  repeat: string,
): PasswordIssue | undefined {
  const bytes = new TextEncoder().encode(next).length;
  if ([...next].length < 8 || bytes > 72 || control.test(next))
    return { field: "next", key: "passwordTooShort" };
  if (next === current) return { field: "next", key: "srvPasswordSame" };
  if (next !== repeat) return { field: "repeat", key: "passwordMismatch" };
  return undefined;
}

/** A rough guide, not a rule: length counts most, then character variety. */
export function passwordStrength(value: string): "weak" | "fair" | "strong" {
  const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) =>
    re.test(value),
  ).length;
  const length = [...value].length;
  if (length >= 16 || (length >= 12 && kinds >= 3)) return "strong";
  if (length >= 10 && kinds >= 2) return "fair";
  return "weak";
}
