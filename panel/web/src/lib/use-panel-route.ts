import { useCallback, useSyncExternalStore } from "react";
import { parseRoute, routeURL } from "./navigation";

function subscribe(changed: () => void) {
  window.addEventListener("hashchange", changed);
  return () => window.removeEventListener("hashchange", changed);
}
const snapshot = () => window.location.hash;

export function usePanelRoute() {
  const hash = useSyncExternalStore(subscribe, snapshot, () => "");
  const route = parseRoute(hash);
  const navigate = useCallback((page: string) => {
    window.location.hash = routeURL(page).slice(1);
    window.scrollTo({ top: 0, behavior: "instant" });
  }, []);
  const updateParams = useCallback(
    (patch: Record<string, string>, push = false) => {
      const current = parseRoute(window.location.hash);
      for (const [key, value] of Object.entries(patch)) {
        if (value) current.params.set(key, value);
        else current.params.delete(key);
      }
      const next = routeURL(current.page, current.params);
      if (next === window.location.hash) return;
      if (push) window.location.hash = next.slice(1);
      else {
        window.history.replaceState(null, "", next);
        window.dispatchEvent(new HashChangeEvent("hashchange"));
      }
    },
    [],
  );
  return { ...route, navigate, updateParams };
}
