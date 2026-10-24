import { useState } from "react";
import type { Connection, Inventory, Preset } from "@/lib/api";
import { creationOptions } from "@/lib/creation-defaults";
export function useConnectionDraft({
  inventory,
  engine,
  original,
}: {
  inventory: Inventory;
  engine: string;
  original?: Connection;
}) {
  const [value, setValue] = useState<Connection>(() =>
    original
      ? structuredClone(original)
      : {
          id: "",
          name: "",
          engine,
          protocol: "tcp",
          bind: ["nftables", "iptables"].includes(engine)
            ? inventory.host.addresses.find((ip) => !ip.includes(":")) || ""
            : "0.0.0.0",
          ports: "",
          strategy: "single",
          enabled: true,
          snat: "masquerade",
          interface: "any",
          targets: [{ ip: "", port: 443, weight: 1 }],
          options: creationOptions(engine),
          revision: "",
        },
  );
  const [baseline] = useState(() => JSON.stringify(value));
  const [preset, setPreset] = useState("custom");
  const capability = inventory.capabilities.find(
    (item) => item.id === value.engine,
  )!;
  const installed = inventory.components.find(
    (item) => item.id === value.engine,
  )?.installed;
  function patch<K extends keyof Connection>(key: K, next: Connection[K]) {
    setValue((current) => ({
      ...current,
      [key]: next,
      ...(key === "targets" &&
      current.targets.length > 1 &&
      (next as Connection["targets"]).length === 1
        ? { strategy: "single" }
        : {}),
    }));
    if (["options", "protocol", "strategy", "routing"].includes(key))
      setPreset("custom");
  }
  function applyPreset(profile: Preset | undefined) {
    setPreset(profile?.id || "custom");
    if (!profile) return;
    setValue((current) => ({
      ...current,
      protocol: profile.protocol || current.protocol,
      strategy:
        current.targets.length > 1
          ? profile.strategy || current.strategy
          : "single",
      options: { ...current.options, ...profile.options },
    }));
  }
  function parseCombinedIP(index: number, input: string) {
    const target = value.targets[index];
    const match =
      input.match(/^\[([^\]]+)\]:(\d+)$/) ||
      input.match(/^(\d+\.\d+\.\d+\.\d+):(\d+)$/);
    patch(
      "targets",
      value.targets.map((item, i) =>
        i === index
          ? {
              ...target,
              ip: match ? match[1] : input,
              ...(match ? { port: Number(match[2]) } : {}),
            }
          : item,
      ),
    );
  }

  function changeEngine(next: string) {
    const cap = inventory.capabilities.find((item) => item.id === next)!;
    setPreset("custom");
    setValue((current) => ({
      ...current,
      engine: next,
      protocol: cap.protocols.includes(current.protocol)
        ? current.protocol
        : cap.protocols[0],
      strategy: "single",
      targets: current.targets.slice(0, 1),
      options: creationOptions(next),
      routing: undefined,
      bind: ["iptables", "nftables"].includes(next)
        ? inventory.host.addresses.find((ip) => !ip.includes(":")) || ""
        : "0.0.0.0",
    }));
  }
  function addTarget() {
    const profile = inventory.presets?.find(
      (p) => p.id === preset && p.engine === value.engine,
    );
    const compatible =
      !profile?.max_targets || value.targets.length + 1 <= profile.max_targets;
    setValue((current) => ({
      ...current,
      targets: [
        ...current.targets,
        { ip: "", port: current.targets[0].port, weight: 1 },
      ],
      strategy:
        current.strategy === "single"
          ? (compatible && profile?.strategy !== "single"
              ? profile?.strategy
              : undefined) || capability.strategies[1]
          : current.strategy,
    }));
    if (!compatible) setPreset("custom");
  }
  return {
    value,
    patch,
    preset,
    applyPreset,
    parseCombinedIP,
    changeEngine,
    addTarget,
    capability,
    installed,
    dirty: JSON.stringify(value) !== baseline,
  };
}
export type ConnectionDraft = ReturnType<typeof useConnectionDraft>;
