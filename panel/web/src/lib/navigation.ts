export const pages = [
  "overview",
  "connections",
  "traffic",
  "nodes",
  "gre",
  "forwarding",
  "haproxy",
  "realm",
  "reverse",
  "components",
  "backups",
  "settings",
] as const;
export type Page = (typeof pages)[number];
export type PanelRoute = { page: Page; params: URLSearchParams };

// Hash routes work with the embedded file server and never change API paths.
export function parseRoute(hash: string): PanelRoute {
  const [path, query = ""] = hash.replace(/^#\/?/, "").split("?", 2);
  const page = pages.includes(path as Page) ? (path as Page) : "overview";
  return { page, params: new URLSearchParams(query) };
}
export function routeURL(page: string, params = new URLSearchParams()): string {
  const safe = pages.includes(page as Page) ? page : "overview";
  return `#/${safe}${params.size ? `?${params}` : ""}`;
}
