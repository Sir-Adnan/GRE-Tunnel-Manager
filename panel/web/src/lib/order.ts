// List order set by drag and drop, saved on the server for every device.
// Order is presentation only; it never changes configuration.
import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { api } from "@/lib/api";
import { applyOrder, mergeOrder } from "./order-list.ts";

export { applyOrder, mergeOrder };

export type OrderList = "connections" | "gre" | "reverse" | "nodes" | "overview";
type Orders = Partial<Record<OrderList, string[]>>;

let orders: Orders = {};
let loaded: Promise<void> | undefined;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());

function load() {
  loaded ??= api<Orders>("order")
    .then((value) => {
      orders = value || {};
      emit();
    })
    .catch(() => {
      loaded = undefined;
    });
  return loaded;
}

/** The saved order of one list and a setter that saves it. */
export function useOrder(list: OrderList) {
  useEffect(() => {
    void load();
  }, []);
  const ids = useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => orders[list],
  );
  const [error, setError] = useState("");
  const save = useCallback(
    async (next: string[]) => {
      const previous = orders[list];
      orders = { ...orders, [list]: next };
      emit();
      try {
        await api("order", { list, ids: next });
        setError("");
        return "";
      } catch (e) {
        orders = { ...orders, [list]: previous };
        emit();
        const message = e instanceof Error ? e.message : String(e);
        setError(message);
        return message;
      }
    },
    [list],
  );
  return { ids, save, error };
}
