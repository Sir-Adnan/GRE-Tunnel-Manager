import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { Inventory } from "@/lib/api";
import { usePoll } from "@/lib/use-poll";

/**
 * Server inventory for the signed-in page. Loads on sign-in, optionally refreshes every 30 s while visible
 * (never during a running job), and is cleared from view on sign-out.
 */
export function useInventory({
  authenticated,
  autoRefresh,
  paused,
}: {
  authenticated: boolean;
  autoRefresh: boolean;
  paused: boolean;
}) {
  const [inventory, setInventory] = useState<Inventory>();
  const [error, setError] = useState("");
  const refresh = useCallback(async () => {
    setInventory(await api<Inventory>("inventory"));
    setError("");
  }, []);
  useEffect(() => {
    if (!authenticated) return;
    let alive = true;
    api<Inventory>("inventory")
      .then((value) => {
        if (alive) {
          setInventory(value);
          setError("");
        }
      })
      .catch((reason) => alive && setError(String(reason)));
    return () => {
      alive = false;
    };
  }, [authenticated]);
  usePoll(
    async (signal) => {
      try {
        const value = await api<Inventory>("inventory", undefined, signal);
        if (!signal.aborted) setInventory(value);
      } catch (reason) {
        if (!signal.aborted) toast.error(String(reason));
      }
    },
    {
      seconds: 30,
      enabled: authenticated && autoRefresh && !paused,
      immediate: false,
    },
  );
  return {
    inventory: authenticated ? inventory : undefined,
    error,
    refresh,
  };
}
