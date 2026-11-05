// Health choices of one owner (framework-free; ProtectionFields renders them).
import type { HealthSettings } from "@/features/operations/types";

export type Protection = {
  monitor: boolean;
  failover: boolean;
  notify: boolean;
  enable_health: boolean;
};

/** The current choices of an owner (defaults for a new one). */
export function protectionOf(settings: HealthSettings | undefined, id?: string): Protection {
  if (!settings || !id)
    return { monitor: true, failover: true, notify: true, enable_health: false };
  return {
    monitor: !(settings.ignore || []).includes(id),
    failover: settings.failover.includes(id),
    notify: !(settings.quiet || []).includes(id),
    enable_health: false,
  };
}

export const sameProtection = (a: Protection, b: Protection) =>
  a.monitor === b.monitor && a.failover === b.failover && a.notify === b.notify && a.enable_health === b.enable_health;
