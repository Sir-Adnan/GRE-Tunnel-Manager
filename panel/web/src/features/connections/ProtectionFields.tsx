// Health and protection choices inside a connection or GRE form: whether the
// server checks are on, whether this owner is monitored, fails over and
// notifies, and an optional confirm-or-revert window for the change itself.
import { HeartPulse, ShieldCheck, BellRing, Undo2, Shuffle } from "lucide-react";
import type { ReactNode } from "react";
import { Switch } from "@/components/ui/switch";
import { Choice } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { useT } from "@/lib/i18n";
import type { HealthSettings } from "@/features/operations/types";
import type { Protection } from "./protection";

function Row({
  icon,
  id,
  title,
  detail,
  checked,
  disabled,
  onChange,
}: {
  icon: ReactNode;
  id: string;
  title: string;
  detail: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (next: boolean) => void;
}) {
  return (
    <label className="protect-row" htmlFor={id} data-disabled={disabled || undefined}>
      <span className="protect-icon" aria-hidden>
        {icon}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-sm font-medium">{title}</span>
        <span className="block text-xs text-muted-foreground">{detail}</span>
      </span>
      <Switch id={id} checked={checked} disabled={disabled} onCheckedChange={onChange} />
    </label>
  );
}

export function ProtectionFields({
  settings,
  value,
  onChange,
  failoverEligible,
  failoverHint,
  safeMinutes,
  onSafeMinutes,
  onAdvanced,
}: {
  settings?: HealthSettings;
  value: Protection;
  onChange: (next: Protection) => void;
  /** Kernel forward with two or more destinations (resolved). */
  failoverEligible?: boolean;
  failoverHint?: string;
  safeMinutes?: number;
  onSafeMinutes?: (minutes: number) => void;
  onAdvanced?: () => void;
}) {
  const t = useT();
  const enabled = Boolean(settings?.enabled) || value.enable_health;
  const set = (patch: Partial<Protection>) => onChange({ ...value, ...patch });
  return (
    <section className="protect-panel" aria-labelledby="protect-title">
      <header className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 id="protect-title" className="text-sm font-semibold">
            {t("protectTitle")}
          </h3>
          <p className="text-xs text-muted-foreground">{t("protectHelp")}</p>
        </div>
        {onAdvanced && (
          <Button type="button" variant="link" size="sm" className="h-auto p-0" onClick={onAdvanced}>
            {t("protectAdvanced")}
          </Button>
        )}
      </header>
      {settings && !settings.enabled && (
        <div className="protect-callout" data-on={value.enable_health || undefined}>
          <span className="min-w-0 flex-1">
            <span className="block text-sm font-medium">{t("protectHealthOff")}</span>
            <span className="block text-xs text-muted-foreground">
              {t("protectHealthOffHelp").replace("{s}", String(settings.interval)).replace("{n}", String(settings.fail_threshold))}
            </span>
          </span>
          <Switch
            aria-label={t("protectTurnOn")}
            checked={value.enable_health}
            onCheckedChange={(next) => set({ enable_health: next })}
          />
        </div>
      )}
      <div className="flex flex-col">
        <Row
          id="protect-monitor"
          icon={<HeartPulse />}
          title={t("protectMonitor")}
          detail={
            settings
              ? t("protectMonitorHelp").replace("{s}", String(settings.interval)).replace("{n}", String(settings.fail_threshold))
              : t("protectMonitorHelpShort")
          }
          checked={value.monitor}
          disabled={!enabled}
          onChange={(monitor) => set({ monitor, failover: monitor && value.failover })}
        />
        {failoverEligible !== undefined && (
          <Row
            id="protect-failover"
            icon={<Shuffle />}
            title={t("protectFailover")}
            detail={failoverHint || t(failoverEligible ? "protectFailoverHelp" : "protectFailoverNeeds")}
            checked={value.failover && Boolean(failoverEligible)}
            disabled={!enabled || !value.monitor || !failoverEligible}
            onChange={(failover) => set({ failover })}
          />
        )}
        <Row
          id="protect-notify"
          icon={<BellRing />}
          title={t("protectNotify")}
          detail={t("protectNotifyHelp")}
          checked={value.notify}
          disabled={!enabled || !value.monitor}
          onChange={(notify) => set({ notify })}
        />
      </div>
      {onSafeMinutes && (
        <div className="protect-safe">
          <span className="protect-icon" aria-hidden>
            {safeMinutes ? <Undo2 /> : <ShieldCheck />}
          </span>
          <div className="min-w-0 flex-1">
            <Choice
              id="safe-minutes"
              label={t("safeApply")}
              help={t("safeApplyHelp")}
              value={String(safeMinutes || 0)}
              choices={[0, 2, 5, 10].map((m) => ({
                value: String(m),
                label: m ? t("safeApplyMinutes").replace("{n}", String(m)) : t("safeApplyOff"),
              }))}
              onChange={(next) => onSafeMinutes(Number(next))}
            />
          </div>
        </div>
      )}
    </section>
  );
}
