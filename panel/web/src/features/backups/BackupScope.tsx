import { KeyRound, Network, ShieldCheck, History, Info } from "lucide-react";
import { useT } from "@/lib/i18n";
import { HelpTip } from "@/components/help";

export function BackupScope() {
  const t = useT();
  return (
    <>
      <div className="flex items-center gap-2 rounded-lg border p-3 text-xs text-muted-foreground xl:hidden">
        <ShieldCheck className="size-4 shrink-0" />
        <span>{t("backupLocalOnly")}</span>
        <HelpTip label={t("backupScope")}>
          <div className="flex flex-col gap-3">
            <p>{t("backupScopeConnections")}</p>
            <p>{t("backupScopeSecrets")}</p>
            <p>{t("backupScopeTraffic")}</p>
            <p>{t("backupExcluded")}</p>
          </div>
        </HelpTip>
      </div>
      <div className="hidden flex-col gap-5 rounded-xl border bg-muted/20 p-5 xl:flex">
        <div className="flex items-center gap-2 font-medium">
          <ShieldCheck className="size-5 text-primary" />
          {t("backupScope")}
        </div>
        <ul className="flex flex-col gap-4 text-sm">
          {[
            { icon: Network, key: "backupScopeConnections" },
            { icon: KeyRound, key: "backupScopeSecrets" },
            { icon: History, key: "backupScopeTraffic" },
          ].map(({ icon: Icon, key }) => (
            <li key={key} className="flex items-start gap-3">
              <Icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
              <span>{t(key)}</span>
            </li>
          ))}
        </ul>
        <div className="flex items-center gap-2 border-t pt-4 text-xs text-muted-foreground">
          <Info className="size-4 shrink-0" />
          {t("backupLocalOnly")}
          <HelpTip label={t("backupLimits")}>{t("backupExcluded")}</HelpTip>
        </div>
      </div>
    </>
  );
}
