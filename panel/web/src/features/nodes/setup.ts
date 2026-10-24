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

export const installerDownload =
  "curl -fsSL --ipv4 https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/node-install.sh -o node-install.sh";

export function controllerCommand(host: string): string | undefined {
  const url = controllerURL(host);
  return url
    ? `${installerDownload} && sudo bash node-install.sh --controller --url '${url}'`
    : undefined;
}

export const agentCommand = `${installerDownload} && sudo bash node-install.sh --agent`;
