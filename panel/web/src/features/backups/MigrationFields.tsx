import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { TextField } from "@/components/shared";
import { HelpTip } from "@/components/help";
import { useT } from "@/lib/i18n";
import type { BackupReview } from "./contract";

export function MigrationFields({
  review,
  addresses,
  interfaces,
  disabled,
  onAddressChange,
  onInterfaceChange,
}: {
  review: BackupReview;
  addresses: Record<string, string>;
  interfaces: Record<string, string>;
  disabled: boolean;
  onAddressChange: (from: string, to: string) => void;
  onInterfaceChange: (from: string, to: string) => void;
}) {
  const t = useT();
  const ips = review.addresses.filter((ip) => ip !== "0.0.0.0" && ip !== "::");
  if (!ips.length && !review.interfaces.length) return null;
  return (
    <section className="flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <h3 className="font-medium">{t("backupMigration")}</h3>
        <HelpTip label={t("backupMigration")}>{t("backupMappingHelp")}</HelpTip>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        {ips.map((ip) => (
          <Field key={ip}>
            <FieldLabel htmlFor={`map-${ip}`} className="flex-wrap">
              <Badge variant="outline">
                {ip.includes(":") ? "IPv6" : "IPv4"}
              </Badge>
              <code dir="ltr" className="break-all text-xs">
                {ip}
              </code>
            </FieldLabel>
            <Input
              id={`map-${ip}`}
              dir="ltr"
              placeholder={t("backupKeepValue")}
              value={addresses[ip] || ""}
              disabled={disabled}
              onChange={(event) => onAddressChange(ip, event.target.value)}
            />
          </Field>
        ))}
        {review.interfaces.map((name) => (
          <TextField
            key={name}
            id={`map-interface-${name}`}
            label={`${t("interface")} · ${name}`}
            dir="ltr"
            placeholder={t("backupKeepValue")}
            value={interfaces[name] || ""}
            disabled={disabled}
            onChange={(event) => onInterfaceChange(name, event.target.value)}
          />
        ))}
      </div>
    </section>
  );
}
