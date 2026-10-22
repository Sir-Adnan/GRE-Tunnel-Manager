import { ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { HelpTip } from "@/components/help";
import { useT } from "@/lib/i18n";

// Browser transport is independent of tunnel protocols and future Agent transport.
export function AccessStatus() {
  const t = useT();
  const encrypted = location.protocol === "https:";
  const Icon = encrypted ? ShieldCheck : ShieldAlert;
  return (
    <span className="flex shrink-0 items-center gap-1">
      <Badge variant="outline">
        <Icon data-icon="inline-start" />
        {encrypted ? "HTTPS" : "HTTP"}
      </Badge>
      <HelpTip label={t("accessSecurity")}>
        {t(encrypted ? "secure" : "httpHelp")}
      </HelpTip>
    </span>
  );
}
