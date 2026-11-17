import { agentCommand as agentInstall } from "../../lib/commands.ts";

/** Only literal addresses or domain names; never interpolate shell syntax. */
export function controllerURL(input: string): string | undefined {
  const host = input.trim().replace(/^\[([^\]]+)\]$/, "$1");
  if (!host || host.length > 253 || !/^[a-zA-Z0-9:.-]+$/.test(host)) return;
  try {
    const url = new URL(
      `https://${host.includes(":") ? `[${host}]` : host}:9443`,
    );
    if (!url.hostname || url.username || url.password) return;
    return url.origin;
  } catch {
    return;
  }
}

/** Run on the panel server: opens the Agent listener (TLS, port 9443). */
export function controllerCommand(host: string): string | undefined {
  const url = controllerURL(host);
  return url ? `sudo gtm controller enable --url '${url}'` : undefined;
}

export const agentCommand = agentInstall();
export const agentTrafficCommand = agentInstall(["--traffic"]);
