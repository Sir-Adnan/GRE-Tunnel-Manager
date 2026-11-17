// Shell commands the panel shows for copying. One place, so every page
// offers the same installer form as the README and docs/INSTALL.md.
//
// `sudo bash -c "$(curl …)"` downloads the whole script before it runs and
// keeps the keyboard on the terminal, so the installer can ask questions
// (and read a hidden enrollment code). Options follow the `@` placeholder.

export const installerURL =
  "https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh";

/** The one-line installer, optionally with fixed options such as --agent. */
export function installCommand(options: readonly string[] = []): string {
  const base = `sudo bash -c "$(curl -fsSL ${installerURL})"`;
  return options.length ? `${base} @ ${options.join(" ")}` : base;
}

/** An outbound Agent on another server; extras: --operations, --traffic. */
export function agentCommand(
  extras: readonly ("--operations" | "--traffic")[] = [],
): string {
  return installCommand(["--agent", ...extras]);
}

export const updateCommand = "sudo gtm update";
export const passwordCommand = "sudo gtm password";
