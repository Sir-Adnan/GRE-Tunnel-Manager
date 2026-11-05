import { useState } from "react";
import type { Connection, Inventory, Preset } from "@/lib/api";
import { creationOptions } from "@/lib/creation-defaults";
import { parseSpans, targetPorts } from "@/lib/ports";
const kernelEngines = ["nftables", "iptables"];
// Every listener defaults to all local addresses. For kernel forwards this keeps
// servers with additional IPs working on each address; a specific IP stays
// available under advanced settings.
const anyAddress = (ipv6: boolean) => (ipv6 ? "::" : "0.0.0.0");
const isAnyAddress = (bind: string) => bind === "0.0.0.0" || bind === "::";
// Kernel rules stay in one address family, so a wildcard follows the first target.
function alignKernelBind(next: Connection): Connection {
  if (!kernelEngines.includes(next.engine) || !isAnyAddress(next.bind))
    return next;
  return {
    ...next,
    bind: anyAddress(Boolean(next.targets[0]?.ip.includes(":"))),
  };
}
/** An edited range record shows its mapping as "same" or "map" when every target agrees. */
function editMapping(c: Connection): Connection {
  const next = structuredClone(c);
  delete next.resolved;
  if (!c.ports.includes("-")) return next;
  const specs = new Set(c.targets.map(targetPorts));
  if (specs.size !== 1) return next;
  const spec = [...specs][0];
  if (spec === c.ports) next.port_mode = "same";
  else if (spec.includes("-")) {
    next.port_mode = "map";
    next.remote_ports = spec;
  }
  return next;
}

export function useConnectionDraft({
  inventory,
  engine,
  original,
  copy,
}: {
  inventory: Inventory;
  engine: string;
  original?: Connection;
  /** A connection to duplicate as a new one. */
  copy?: Connection;
}) {
  const [value, setValue] = useState<Connection>(() =>
    original
      ? editMapping(original)
      : copy
        ? { ...editMapping(copy), id: "", revision: "", status: undefined }
        : {
          id: "",
          name: "",
          engine,
          protocol: "tcp",
          bind: anyAddress(false),
          ports: "",
          strategy: "single",
          enabled: true,
          snat: "masquerade",
          interface: "any",
          targets: [{ ip: "", port: 443, weight: 1 }],
          options: creationOptions(engine),
          revision: "",
          port_mode: "",
        },
  );
  // Several ports or a range default to the same remote port numbers until
  // the person picks a mapping.
  const [modeTouched, setModeTouched] = useState(Boolean(original));
  const [baseline] = useState(() => JSON.stringify(value));
  const [preset, setPreset] = useState("custom");
  const capability = inventory.capabilities.find(
    (item) => item.id === value.engine,
  )!;
  const installed = inventory.components.find(
    (item) => item.id === value.engine,
  )?.installed;
  function patch<K extends keyof Connection>(key: K, next: Connection[K]) {
    if (key === "port_mode") setModeTouched(true);
    setValue((current) => {
      const kernel = kernelEngines.includes(current.engine);
      const spans =
        key === "ports" ? parseSpans(String(next), kernel).spans : [];
      const several =
        spans.length > 1 || spans.some((s) => s.last > s.first);
      const updated = {
        ...current,
        [key]: next,
        ...(key === "ports" && !modeTouched
          ? { port_mode: several ? ("same" as const) : ("" as const) }
          : {}),
        ...(key === "strategy" &&
        next === "failover" &&
        current.options.check_mode === "off"
          ? { options: { ...current.options, check_mode: "tcp" } }
          : {}),
        ...(key === "targets" &&
        current.targets.length > 1 &&
        (next as Connection["targets"]).length === 1
          ? { strategy: "single" }
          : {}),
      };
      return key === "targets" ? alignKernelBind(updated) : updated;
    });
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
      options: { ...creationOptions(current.engine), ...profile.options },
      routing: undefined,
    }));
  }
  function resetDefaults() {
    setPreset("defaults");
    setValue((current) => ({
      ...current,
      options: creationOptions(current.engine),
      routing: undefined,
      strategy:
        current.targets.length === 1
          ? "single"
          : current.engine === "haproxy"
            ? "leastconn"
            : capability.strategies[1],
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
      bind: kernelEngines.includes(next)
        ? anyAddress(Boolean(current.targets[0]?.ip.includes(":")))
        : anyAddress(false),
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
  /** Moves a destination (its order is its priority for failover). */
  function moveTargets(order: number[]) {
    setValue((current) => ({
      ...current,
      targets: order.map((i) => current.targets[i]),
    }));
  }
  return {
    value,
    patch,
    moveTargets,
    preset,
    applyPreset,
    resetDefaults,
    parseCombinedIP,
    changeEngine,
    addTarget,
    capability,
    installed,
    // Wildcard first, then this server's addresses (additional IPs included).
    bindSuggestions: [
      ...new Set([
        anyAddress(Boolean(value.targets[0]?.ip.includes(":"))),
        ...inventory.host.addresses,
      ]),
    ],
    dirty: JSON.stringify(value) !== baseline,
  };
}
export type ConnectionDraft = ReturnType<typeof useConnectionDraft>;
