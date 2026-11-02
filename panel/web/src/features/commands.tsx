import { useMemo } from "react";
import {
  Languages,
  Monitor,
  Moon,
  Palette,
  Plus,
  RefreshCw,
  Route,
  Sun,
} from "lucide-react";
import type { Command } from "@/components/CommandPalette";
import { navItems } from "@/components/nav-items";
import { styleChoices } from "@/experience/style-choices";
import { engineName } from "@/lib/format";
import { engineFilters } from "@/lib/connection-filters";
import type { Inventory } from "@/lib/api";
import type { Preferences } from "@/lib/preferences";

const createEngines = ["haproxy", "realm", "nftables", "iptables"];

/** Everything the command palette can do, in the viewer's language. */
export function usePanelCommands({
  t,
  inventory,
  preferences,
  setPreferences,
  navigate,
  add,
  refresh,
}: {
  t: (key: string) => string;
  inventory?: Inventory;
  preferences: Preferences;
  setPreferences: (value: Preferences) => void;
  navigate: (page: string, params?: Record<string, string>) => void;
  add: (engine: string, engines?: string[]) => void;
  refresh: () => void;
}): Command[] {
  return useMemo(() => {
    const go = t("commandGo"),
      create = t("commandCreate"),
      look = t("appearance"),
      saved = t("connections");
    const commands: Command[] = [
      ...navItems.map(({ id, icon: Icon }) => ({
        id: `go-${id}`,
        group: go,
        label: t(id),
        keywords: id,
        icon: <Icon />,
        run: () => navigate(id),
      })),
      ...engineFilters
        .filter((id) => id !== "all")
        .map((id) => ({
          id: `filter-${id}`,
          group: go,
          label: `${t("connections")} · ${id === "kernel" ? t("forwarding") : engineName(id)}`,
          keywords: `${id} filter nftables iptables`,
          icon: <Route />,
          run: () => navigate("connections", { engine: id }),
        })),
      ...createEngines.map((engine) => ({
        id: `create-${engine}`,
        group: create,
        label: `${t("newConnection")} · ${engineName(engine)}`,
        keywords: `new add ${engine}`,
        icon: <Plus />,
        run: () => add(engine),
      })),
      ...styleChoices(preferences.locale, preferences.style).map((item) => ({
        id: `style-${item.id}`,
        group: look,
        label: `${t("style")}: ${item.name}`,
        keywords: `theme ${item.id}`,
        hint: item.id === preferences.style ? "✓" : undefined,
        icon: <Palette />,
        run: () => setPreferences({ ...preferences, style: item.id }),
      })),
      ...(
        [
          ["light", Sun],
          ["dark", Moon],
          ["system", Monitor],
        ] as const
      ).map(([mode, Icon]) => ({
        id: `mode-${mode}`,
        group: look,
        label: `${t("mode")}: ${t(mode)}`,
        keywords: `mode theme ${mode}`,
        hint: mode === preferences.mode ? "✓" : undefined,
        icon: <Icon />,
        run: () => setPreferences({ ...preferences, mode }),
      })),
      {
        id: "language",
        group: look,
        label: preferences.locale === "fa" ? "English" : "فارسی",
        keywords: "language locale زبان",
        icon: <Languages />,
        run: () =>
          setPreferences({
            ...preferences,
            locale: preferences.locale === "fa" ? "en" : "fa",
          }),
      },
      {
        id: "refresh",
        group: look,
        label: t("refresh"),
        keywords: "reload",
        icon: <RefreshCw />,
        run: refresh,
      },
    ];
    for (const c of inventory?.connections || [])
      commands.push({
        id: `connection-${c.id}`,
        group: saved,
        label: c.name,
        keywords: `${c.id} ${c.engine} ${c.ports} ${c.targets.map((x) => x.ip).join(" ")}`,
        hint: `${engineName(c.engine)} · ${c.ports}`,
        icon: <Route />,
        run: () => navigate("connections", { connection: c.id }),
      });
    return commands;
  }, [t, inventory, preferences, setPreferences, navigate, add, refresh]);
}
