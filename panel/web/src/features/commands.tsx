import { useMemo } from "react";
import {
  Activity,
  Code2,
  CopyPlus,
  Info,
  Languages,
  Monitor,
  Moon,
  Palette,
  Pencil,
  Plus,
  Power,
  RefreshCw,
  Replace,
  Route,
  Rows2,
  Rows4,
  Sun,
  Trash2,
  Waypoints,
} from "lucide-react";
import type { Command } from "@/components/CommandPalette";
import { navItems } from "@/components/nav-items";
import { styleChoices } from "@/experience/style-choices";
import { engineName } from "@/lib/format";
import { engineFilters } from "@/lib/connection-filters";
import type { Connection, Inventory } from "@/lib/api";
import { densities, type Preferences } from "@/lib/preferences";
import {
  availableTemplates,
  templateDraft,
  type TemplateID,
} from "@/lib/templates";

const createEngines = ["haproxy", "realm", "nftables", "iptables"];

/** Everything the command palette can do, in the viewer's language. */
export function usePanelCommands({
  t,
  inventory,
  preferences,
  setPreferences,
  navigate,
  add,
  edit,
  duplicate,
  run,
  refresh,
}: {
  t: (key: string) => string;
  inventory?: Inventory;
  preferences: Preferences;
  setPreferences: (value: Preferences) => void;
  navigate: (page: string, params?: Record<string, string>) => void;
  add: (engine: string, engines?: string[], template?: TemplateID) => void;
  edit: (connection: Connection) => void;
  duplicate: (connection: Connection) => void;
  run: (request: unknown) => Promise<void>;
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
      ...(inventory ? availableTemplates(inventory) : []).map((id) => ({
        id: `template-${id}`,
        group: create,
        label: `${t("newConnection")} · ${t(`tmpl_${id}`)}`,
        keywords: `new template ${id} vpn`,
        icon: <Plus />,
        run: () =>
          inventory && add(templateDraft(id, inventory).engine, undefined, id),
      })),
      {
        id: "two-servers",
        group: create,
        label: t("wizTitle"),
        keywords: "gre tunnel two servers wizard foreign iran kharej دو سرور تونل خارج",
        icon: <Waypoints />,
        run: () => navigate("connections", { wizard: "gre" }),
      },
      {
        id: "ip-changed",
        group: create,
        label: t("ipChangeTitle"),
        keywords: "ip address changed readdress move آی‌پی عوض تغییر",
        icon: <Replace />,
        run: () => navigate("addresses", { change: "1" }),
      },
      {
        id: "ip-extra",
        group: create,
        label: t("ipExtraAdd"),
        keywords: "additional extra secondary ip address آی‌پی اضافه",
        icon: <Plus />,
        run: () => navigate("addresses", { extra: "1" }),
      },
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
      ...densities.map((density) => ({
        id: `density-${density}`,
        group: look,
        label: `${t("density")}: ${t(density)}`,
        keywords: `density spacing ${density} تراکم`,
        hint: density === preferences.density ? "✓" : undefined,
        icon: density === "compact" ? <Rows4 /> : <Rows2 />,
        run: () => setPreferences({ ...preferences, density }),
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
        children: connectionCommands(c),
      });
    return commands;

    /** The second step for one connection: what to do with it. */
    function connectionCommands(c: Connection): Command[] {
      const group = t("commandActions"),
        open = (params: Record<string, string>) =>
          navigate("connections", params);
      return [
        {
          id: "details",
          label: t("connectionDetails"),
          icon: <Info />,
          run: () => open({ connection: c.id }),
        },
        {
          id: "check",
          label: t("chkTab"),
          keywords: "check path test",
          icon: <Activity />,
          run: () => open({ connection: c.id, detail: "check" }),
        },
        {
          id: "edit",
          label: t("edit"),
          icon: <Pencil />,
          run: () => edit(c),
        },
        {
          id: "toggle",
          label: t(c.enabled ? "turnOff" : "turnOn"),
          keywords: "enable disable on off",
          icon: <Power />,
          run: () =>
            void run({
              action: c.enabled ? "disable" : "enable",
              selected: [{ id: c.id, revision: c.revision }],
            }).catch(() => {}),
        },
        {
          id: "duplicate",
          label: t("duplicate"),
          icon: <CopyPlus />,
          run: () => duplicate(c),
        },
        {
          id: "config",
          label: t("viewConfig"),
          icon: <Code2 />,
          run: () => open({ config: c.id }),
        },
        {
          id: "delete",
          label: t("delete"),
          keywords: "remove",
          icon: <Trash2 />,
          run: () => open({ remove: c.id }),
        },
      ].map((command) => ({ ...command, group }));
    }
  }, [
    t,
    inventory,
    preferences,
    setPreferences,
    navigate,
    add,
    edit,
    duplicate,
    run,
    refresh,
  ]);
}
