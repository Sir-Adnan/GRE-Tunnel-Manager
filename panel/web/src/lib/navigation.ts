export const pages = [
  "overview",
  "connections",
  "traffic",
  "health",
  "nodes",
  "gre",
  "reverse",
  "maintenance",
  "components",
  "backups",
  "settings",
] as const;
export type Page = (typeof pages)[number];
export type PanelRoute = { page: Page; params: URLSearchParams };

/** Engine pages from v1.3 are one filtered Connections page now; their bookmarks keep working. */
export const legacyEnginePages: Readonly<Record<string, string>> = {
  forwarding: "kernel",
  haproxy: "haproxy",
  realm: "realm",
};

function resolve(path: string, params: URLSearchParams): PanelRoute {
  const engine = Object.hasOwn(legacyEnginePages, path)
    ? legacyEnginePages[path]
    : undefined;
  if (engine) {
    if (!params.has("engine")) params.set("engine", engine);
    return { page: "connections", params };
  }
  const page = pages.includes(path as Page) ? (path as Page) : "overview";
  return { page, params };
}

// Hash routes work with the embedded file server and never change API paths.
export function parseRoute(hash: string): PanelRoute {
  const [path, query = ""] = hash.replace(/^#\/?/, "").split("?", 2);
  return resolve(path, new URLSearchParams(query));
}
export function routeURL(page: string, params = new URLSearchParams()): string {
  const route = resolve(page, new URLSearchParams(params));
  return `#/${route.page}${route.params.size ? `?${route.params}` : ""}`;
}
