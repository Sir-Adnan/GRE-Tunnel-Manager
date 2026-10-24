import { Choice, TextField } from "@/components/shared";
import type { Inventory } from "@/lib/api";
import { useT } from "@/lib/i18n";

const network = new Set([
  "proxy",
  "log",
  "send_mptcp",
  "accept_mptcp",
  "ipv6_only",
  "listen_transport",
  "remote_transport",
  "ws_host",
  "ws_path",
  "send_proxy",
  "send_proxy_version",
  "accept_proxy",
  "accept_proxy_timeout",
]);
const specializedHA = new Set([
  "check_mode",
  "check_port",
  "check_path",
  "check_host",
  "check_status",
  "stick",
  "stick_size",
  "stick_expire",
]);

export function EngineOptionFields({
  capability,
  options,
  section,
  onChange,
}: {
  capability: Inventory["capabilities"][number];
  options: Record<string, string>;
  section: "limits" | "network";
  onChange: (options: Record<string, string>) => void;
}) {
  const t = useT();
  return capability.options
    .filter(
      (o) =>
        !(capability.id === "haproxy" && specializedHA.has(o.key)) &&
        network.has(o.key) === (section === "network"),
    )
    .map((option) =>
      option.choices ? (
        <Choice
          key={option.key}
          id={`option-${option.key}`}
          label={t(option.key)}
          value={options[option.key] ?? option.default}
          choices={option.choices.map((id) => ({ value: id, label: t(id) }))}
          onChange={(next) => onChange({ ...options, [option.key]: next })}
        />
      ) : (
        <TextField
          key={option.key}
          id={`option-${option.key}`}
          label={t(option.key)}
          help={option.key === "maxconn" ? t("maxconnHelp") : undefined}
          type={option.format ? "text" : "number"}
          min={option.min}
          max={option.max}
          dir="ltr"
          value={options[option.key] ?? option.default}
          onChange={(e) =>
            onChange({ ...options, [option.key]: e.target.value })
          }
          required
        />
      ),
    );
}
