import { useContext } from "react";
import {
  Copy,
  Ellipsis,
  FlaskConical,
  Pencil,
  Play,
  Power,
  RefreshCw,
  RotateCw,
  Trash,
  type LucideIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Switch } from "@/components/ui/switch";
import { LocaleContext, useT } from "@/lib/i18n";
import type { Owner, PlanView } from "@/features/operations/types";
import { duration, stamp } from "@/features/health/format";
import { scopedOwners, triggerSummary } from "./plans";

const actionIcons: Record<string, LucideIcon> = {
  refresh: RefreshCw,
  restart: RotateCw,
  reboot: Power,
};

export function ResultBadge({ result }: { result?: string }) {
  const t = useT();
  if (!result) return null;
  return (
    <span className="result-badge" data-result={result}>
      {t(`result_${result}`)}
    </span>
  );
}

function chips(plan: PlanView, t: (k: string) => string, locale: "fa" | "en") {
  const g = plan.guards;
  const out: string[] = [];
  if (g.window)
    out.push(t("chipWindow").replace("{w}", g.window.replace("-", "–")));
  if (g.quiet_mbps)
    out.push(t("chipQuiet").replace("{n}", String(g.quiet_mbps)));
  if (g.cooldown)
    out.push(
      t("chipCooldown").replace("{d}", duration(g.cooldown * 60, locale)),
    );
  out.push(t("chipMax").replace("{n}", String(g.max_per_day)));
  if (g.notice) out.push(t("chipNotice").replace("{n}", String(g.notice)));
  if (plan.action === "reboot" && g.min_uptime)
    out.push(
      t("chipMinUptime").replace("{d}", duration(g.min_uptime * 60, locale)),
    );
  return out;
}

export function PlanCard({
  plan,
  owners,
  timezone,
  moduleEnabled,
  busy,
  toggle,
  edit,
  duplicate,
  remove,
  runNow,
}: {
  plan: PlanView;
  owners: Owner[];
  timezone: string;
  moduleEnabled: boolean;
  busy: boolean;
  toggle: (enabled: boolean) => void;
  edit: () => void;
  duplicate: () => void;
  remove: () => void;
  runNow: () => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const Icon = actionIcons[plan.action];
  const scoped = scopedOwners(plan, owners);
  const scopeText =
    plan.action === "reboot" && plan.trigger.kind !== "health"
      ? t("mxScopeServer")
      : plan.scope.length
        ? scoped.map((o) => o.name).join(locale === "fa" ? "، " : ", ")
        : t("mxScopeAll").replace("{n}", String(scoped.length));
  const next =
    !plan.enabled || !moduleEnabled
      ? t("mxPaused")
      : plan.trigger.kind === "health"
        ? t("mxOnTrigger")
        : plan.state.next
          ? stamp(plan.state.next, locale, timezone)
          : "—";
  return (
    <article
      className="plan-card"
      data-action={plan.action}
      data-enabled={plan.enabled}
    >
      <header className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-3">
          <span className="plan-icon">
            <Icon className="size-4" />
          </span>
          <div className="flex min-w-0 flex-col gap-1">
            <h3 className="truncate text-sm font-semibold">
              <bdi>{plan.name}</bdi>
            </h3>
            <div className="flex flex-wrap items-center gap-1.5">
              <Badge variant="outline">{t(`action_${plan.action}`)}</Badge>
              {plan.dry_run && (
                <Badge variant="secondary" className="gap-1">
                  <FlaskConical />
                  {t("mxDryRun")}
                </Badge>
              )}
            </div>
          </div>
        </div>
        <Switch
          checked={plan.enabled}
          disabled={busy}
          onCheckedChange={toggle}
          aria-label={`${t("mxEnabled")} · ${plan.name}`}
        />
      </header>
      <p className="text-sm">
        <bdi>{triggerSummary(plan, t, (d) => t(`day_${d}`))}</bdi>
      </p>
      <p className="truncate text-xs text-muted-foreground" title={scopeText}>
        {t("mxScope")}: <bdi>{scopeText}</bdi>
      </p>
      <ul className="chip-list">
        {chips(plan, t, locale).map((chip) => (
          <li key={chip}>
            <bdi>{chip}</bdi>
          </li>
        ))}
      </ul>
      {plan.state.note && (
        <p className="text-xs text-warning-text">
          {t(`msg:${plan.state.note}`).replace(/^msg:/, "")}
        </p>
      )}
      <footer className="plan-footer">
        <dl>
          <div>
            <dt>{t("mxNext")}</dt>
            <dd>
              <bdi>{next}</bdi>
            </dd>
          </div>
          <div>
            <dt>{t("mxLast")}</dt>
            <dd className="flex items-center gap-1.5">
              {plan.state.last ? (
                <>
                  <bdi>{stamp(plan.state.last, locale, timezone)}</bdi>
                  <ResultBadge result={plan.state.last_result} />
                </>
              ) : (
                t("mxNever")
              )}
            </dd>
          </div>
        </dl>
        <div className="flex items-center gap-1">
          <Button
            variant="outline"
            size="sm"
            disabled={busy || Boolean(plan.state.pending)}
            onClick={runNow}
          >
            <Play data-icon="inline-start" />
            {t("mxRunNow")}
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label={`${t("actions")} · ${plan.name}`}
              >
                <Ellipsis />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onSelect={edit}>
                <Pencil />
                {t("edit")}
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={duplicate}>
                <Copy />
                {t("mxDuplicate")}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem variant="destructive" onSelect={remove}>
                <Trash />
                {t("mxDeletePlan")}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </footer>
    </article>
  );
}
