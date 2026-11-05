import { useContext, useMemo, useState, type ReactNode } from "react";
import {
  ChevronDown,
  Loader2,
  Plus,
  Power,
  RefreshCw,
  RotateCw,
  TriangleAlert,
  X,
  type LucideIcon,
} from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Segmented } from "@/components/Segmented";
import { Choice, EngineGlyph, TextField } from "@/components/shared";
import { HelpTip } from "@/components/help";
import { engineName } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import type {
  Action,
  Owner,
  Plan,
  TriggerKind,
} from "@/features/operations/types";
import {
  applies,
  cleanPlan,
  newPlan,
  templates,
  triggerKinds,
  triggerSummary,
  validatePlan,
  weekOrder,
} from "./plans";

const actionIcon: Record<Action, LucideIcon> = {
  refresh: RefreshCw,
  restart: RotateCw,
  reboot: Power,
};
const impact: Record<Action, string> = {
  refresh: "impact_none",
  restart: "impact_brief",
  reboot: "impact_all",
};

function Section({
  title,
  help,
  children,
}: {
  title: string;
  help?: string;
  children: ReactNode;
}) {
  return (
    <fieldset className="editor-section">
      <legend className="flex items-center gap-1">
        {title}
        {help && <HelpTip>{help}</HelpTip>}
      </legend>
      {children}
    </fieldset>
  );
}

function NumberField({
  id,
  label,
  help,
  value,
  onChange,
  min,
  max,
}: {
  id: string;
  label: string;
  help?: string;
  value: number | undefined;
  onChange: (value: number) => void;
  min: number;
  max: number;
}) {
  return (
    <TextField
      id={id}
      label={label}
      help={help}
      type="number"
      inputMode="numeric"
      dir="ltr"
      min={min}
      max={max}
      value={value === undefined ? "" : String(value)}
      onChange={(event) =>
        onChange(event.target.value === "" ? 0 : Number(event.target.value))
      }
    />
  );
}

function Templates({ choose }: { choose: (plan: Plan) => void }) {
  const t = useT();
  return (
    <div className="template-grid">
      {templates.map((template) => {
        const Icon = actionIcon[template.action];
        return (
          <button
            key={template.id}
            type="button"
            className="template-card"
            data-action={template.action}
            onClick={() =>
              choose({ ...template.plan(), name: t(`tpl_${template.id}`) })
            }
          >
            <span className="template-icon">
              <Icon className="size-4" />
            </span>
            <span className="flex min-w-0 flex-col gap-1 text-start">
              <strong className="text-sm font-medium">
                {t(`tpl_${template.id}`)}
              </strong>
              <span className="text-xs text-muted-foreground">
                {t(`tpl_${template.id}Help`)}
              </span>
            </span>
          </button>
        );
      })}
      <button
        type="button"
        className="template-card is-blank"
        onClick={() => choose(newPlan())}
      >
        <span className="template-icon">
          <Plus className="size-4" />
        </span>
        <strong className="text-sm font-medium">{t("mxBlank")}</strong>
      </button>
    </div>
  );
}

export function PlanEditor({
  open,
  initial,
  owners,
  healthEnabled,
  conntrackCLI,
  onClose,
  save,
}: {
  open: boolean;
  initial?: Plan;
  owners: Owner[];
  healthEnabled: boolean;
  conntrackCLI: boolean;
  onClose: () => void;
  save: (plan: Plan) => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [plan, setPlan] = useState<Plan | undefined>(initial);
  const [busy, setBusy] = useState(false);
  const [guardsOpen, setGuardsOpen] = useState(false);
  const [tried, setTried] = useState(false);
  // An automatic reboot plan needs a second, explicit confirmation.
  const [armed, setArmed] = useState(false);
  const draft = plan;
  const risky = Boolean(
    draft && draft.action === "reboot" && draft.enabled && !draft.dry_run,
  );
  const supported = useMemo(
    () =>
      draft
        ? owners.filter(
            (o) => draft.action === "reboot" || applies(draft.action, o.engine),
          )
        : [],
    [owners, draft],
  );
  const update = (patch: Partial<Plan>) => {
    setArmed(false);
    if (draft) setPlan({ ...draft, ...patch });
  };
  const trigger = (patch: Partial<Plan["trigger"]>) =>
    draft && setPlan({ ...draft, trigger: { ...draft.trigger, ...patch } });
  const guards = (patch: Partial<Plan["guards"]>) =>
    draft && setPlan({ ...draft, guards: { ...draft.guards, ...patch } });
  const problem = draft ? validatePlan(cleanPlan(draft)) : "";
  const dayName = (day: number) => t(`day_${day}`);
  const serverWide =
    draft?.action === "reboot" && draft.trigger.kind !== "health";
  const kernelRestart =
    draft?.action === "restart" &&
    !conntrackCLI &&
    supported.some(
      (o) =>
        (o.engine === "nftables" || o.engine === "iptables") &&
        (!draft.scope.length || draft.scope.includes(o.id)),
    );
  const [from, to] = (draft?.guards.window ?? "").split("-");
  const setWindow = (a: string, b: string) =>
    guards({ window: a || b ? `${a}-${b}` : "" });
  return (
    <Dialog open={open} onOpenChange={(next) => !next && !busy && onClose()}>
      <DialogContent
        closeLabel={t("close")}
        scrollLayout="body"
        className="sm:max-w-2xl"
      >
        <DialogHeader>
          <DialogTitle>
            {t(initial?.id ? "mxEditPlan" : "mxNewPlan")}
          </DialogTitle>
          <DialogDescription>
            {t(draft ? "maintenanceIntro" : "mxEmptyBody")}
          </DialogDescription>
        </DialogHeader>
        {!draft ? (
          <DialogBody>
            <Templates choose={(p) => setPlan(p)} />
          </DialogBody>
        ) : (
          <>
            <DialogBody>
              <form
                id="plan-editor"
                className="flex flex-col gap-5"
                onSubmit={(event) => {
                  event.preventDefault();
                  setTried(true);
                  if (problem) return;
                  if (risky && !armed) {
                    setArmed(true);
                    return;
                  }
                  setBusy(true);
                  save(cleanPlan(draft))
                    .then(onClose)
                    .catch(() => undefined)
                    .finally(() => setBusy(false));
                }}
              >
                <TextField
                  id="plan-name"
                  label={t("mxPlanName")}
                  value={draft.name}
                  maxLength={60}
                  required
                  onChange={(event) => update({ name: event.target.value })}
                />
                <Section title={t("mxAction")}>
                  <div
                    className="action-grid"
                    role="radiogroup"
                    aria-label={t("mxAction")}
                  >
                    {(["refresh", "restart", "reboot"] as Action[]).map(
                      (action) => {
                        const Icon = actionIcon[action];
                        const selected = draft.action === action;
                        return (
                          <button
                            key={action}
                            type="button"
                            role="radio"
                            aria-checked={selected}
                            data-action={action}
                            className="action-card"
                            onClick={() =>
                              update({
                                action,
                                trigger:
                                  action !== "reboot" &&
                                  draft.trigger.kind === "uptime"
                                    ? {
                                        kind: "daily",
                                        times: draft.trigger.times ?? ["04:30"],
                                      }
                                    : draft.trigger,
                                guards:
                                  action === "reboot"
                                    ? {
                                        min_uptime: 30,
                                        notice: 5,
                                        ...draft.guards,
                                      }
                                    : draft.guards,
                              })
                            }
                          >
                            <span className="flex items-center gap-2">
                              <Icon className="size-4" />
                              <strong className="text-sm font-medium">
                                {t(`action_${action}`)}
                              </strong>
                            </span>
                            <Badge variant="outline" className="action-impact">
                              {t(impact[action])}
                            </Badge>
                          </button>
                        );
                      },
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {t(`action_${draft.action}Help`)}
                  </p>
                </Section>
                <Section
                  title={
                    draft.action === "reboot" && !serverWide
                      ? t("mxScopeWatch")
                      : t("mxScope")
                  }
                >
                  {serverWide ? (
                    <p className="text-sm">{t("mxScopeServer")}</p>
                  ) : supported.length === 0 ? (
                    <p className="text-sm text-muted-foreground">
                      {t("mxScopeNone")}
                    </p>
                  ) : (
                    <>
                      <Segmented
                        label={t("mxScope")}
                        value={draft.scope.length ? "some" : "all"}
                        onChange={(value) =>
                          update({
                            scope: value === "all" ? [] : [supported[0].id],
                          })
                        }
                        options={[
                          {
                            value: "all",
                            label: t("mxScopeAll").replace(
                              "{n}",
                              String(supported.length),
                            ),
                          },
                          { value: "some", label: t("mxScopeSome") },
                        ]}
                      />
                      {draft.scope.length > 0 && (
                        <ul className="scope-list">
                          {supported.map((owner) => {
                            const checked = draft.scope.includes(owner.id);
                            return (
                              <li key={owner.id}>
                                <label className="scope-item">
                                  <Checkbox
                                    checked={checked}
                                    onCheckedChange={(value) =>
                                      update({
                                        scope: value
                                          ? [...draft.scope, owner.id]
                                          : draft.scope.filter(
                                              (id) => id !== owner.id,
                                            ),
                                      })
                                    }
                                  />
                                  <EngineGlyph
                                    engine={owner.engine}
                                    className="size-4 text-muted-foreground"
                                  />
                                  <span className="truncate text-sm">
                                    <bdi>{owner.name}</bdi>
                                  </span>
                                  <span className="ms-auto text-xs text-muted-foreground">
                                    {engineName(owner.engine)}
                                  </span>
                                </label>
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </>
                  )}
                </Section>
                <Section title={t("mxWhen")}>
                  <Choice
                    id="plan-trigger"
                    label={t("mxTrigger")}
                    labelHidden
                    value={draft.trigger.kind}
                    onChange={(kind) =>
                      trigger({
                        kind: kind as TriggerKind,
                        times: draft.trigger.times?.length
                          ? draft.trigger.times
                          : ["04:30"],
                        hours: draft.trigger.hours ?? 6,
                        days: draft.trigger.days?.length
                          ? draft.trigger.days
                          : [5],
                        uptime_days: draft.trigger.uptime_days ?? 7,
                        condition: draft.trigger.condition ?? "down",
                        minutes: draft.trigger.minutes ?? 3,
                        latency_ms: draft.trigger.latency_ms ?? 400,
                      })
                    }
                    choices={triggerKinds
                      .filter(
                        (kind) =>
                          kind !== "uptime" || draft.action === "reboot",
                      )
                      .map((kind) => ({
                        value: kind,
                        label: t(`trigger_${kind}`),
                      }))}
                  />
                  {draft.trigger.kind === "interval" && (
                    <NumberField
                      id="plan-hours"
                      label={t("mxHours")}
                      min={1}
                      max={168}
                      value={draft.trigger.hours}
                      onChange={(hours) => trigger({ hours })}
                    />
                  )}
                  {draft.trigger.kind === "weekly" && (
                    <div className="flex flex-col gap-2">
                      <span className="text-sm font-medium">{t("mxDays")}</span>
                      <div className="day-picker">
                        {weekOrder(locale).map((day) => {
                          const on = draft.trigger.days?.includes(day) ?? false;
                          return (
                            <button
                              key={day}
                              type="button"
                              aria-pressed={on}
                              className="day-chip"
                              onClick={() =>
                                trigger({
                                  days: on
                                    ? (draft.trigger.days ?? []).filter(
                                        (d) => d !== day,
                                      )
                                    : [...(draft.trigger.days ?? []), day],
                                })
                              }
                            >
                              {dayName(day)}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  )}
                  {draft.trigger.kind === "uptime" && (
                    <NumberField
                      id="plan-uptime"
                      label={t("mxUptimeDays")}
                      min={1}
                      max={60}
                      value={draft.trigger.uptime_days}
                      onChange={(uptime_days) => trigger({ uptime_days })}
                    />
                  )}
                  {["daily", "weekly", "uptime"].includes(
                    draft.trigger.kind,
                  ) && (
                    <div className="flex flex-col gap-2">
                      <span className="text-sm font-medium">
                        {t("mxTimes")}
                      </span>
                      <div className="time-list">
                        {(draft.trigger.times ?? []).map((value, index) => (
                          <div key={index} className="time-item">
                            <Input
                              type="time"
                              dir="ltr"
                              aria-label={`${t("mxTimes")} ${index + 1}`}
                              value={value}
                              onChange={(event) => {
                                const times = [...(draft.trigger.times ?? [])];
                                times[index] = event.target.value;
                                trigger({ times });
                              }}
                            />
                            {(draft.trigger.times?.length ?? 0) > 1 && (
                              <Button
                                type="button"
                                variant="ghost"
                                size="icon-sm"
                                aria-label={t("mxRemoveTime")}
                                onClick={() =>
                                  trigger({
                                    times: (draft.trigger.times ?? []).filter(
                                      (_, i) => i !== index,
                                    ),
                                  })
                                }
                              >
                                <X />
                              </Button>
                            )}
                          </div>
                        ))}
                        {(draft.trigger.times?.length ?? 0) < 6 && (
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              trigger({
                                times: [
                                  ...(draft.trigger.times ?? []),
                                  "12:00",
                                ],
                              })
                            }
                          >
                            <Plus data-icon="inline-start" />
                            {t("mxAddTime")}
                          </Button>
                        )}
                      </div>
                    </div>
                  )}
                  {draft.trigger.kind === "health" && (
                    <div className="grid gap-4 sm:grid-cols-3">
                      <Choice
                        id="plan-condition"
                        label={t("mxCondition")}
                        value={draft.trigger.condition ?? "down"}
                        onChange={(condition) =>
                          trigger({
                            condition: condition as "down" | "latency",
                          })
                        }
                        choices={[
                          { value: "down", label: t("condition_down") },
                          { value: "latency", label: t("condition_latency") },
                        ]}
                      />
                      <NumberField
                        id="plan-minutes"
                        label={t("mxForMinutes")}
                        min={1}
                        max={120}
                        value={draft.trigger.minutes}
                        onChange={(minutes) => trigger({ minutes })}
                      />
                      {draft.trigger.condition === "latency" && (
                        <NumberField
                          id="plan-latency"
                          label={t("mxLatencyAbove")}
                          min={20}
                          max={5000}
                          value={draft.trigger.latency_ms}
                          onChange={(latency_ms) => trigger({ latency_ms })}
                        />
                      )}
                    </div>
                  )}
                  {draft.trigger.kind === "health" && !healthEnabled && (
                    <Alert>
                      <TriangleAlert />
                      <AlertDescription>{t("mxHealthOff")}</AlertDescription>
                    </Alert>
                  )}
                </Section>
                <div className="editor-section">
                  <button
                    type="button"
                    className="guards-toggle"
                    aria-expanded={guardsOpen}
                    onClick={() => setGuardsOpen(!guardsOpen)}
                  >
                    <span className="flex flex-col items-start gap-0.5">
                      <span className="text-sm font-medium">
                        {t("mxGuards")}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {t("mxGuardsHelp")}
                      </span>
                    </span>
                    <ChevronDown
                      className={cn(
                        "size-4 transition-transform",
                        guardsOpen && "rotate-180",
                      )}
                    />
                  </button>
                  {guardsOpen && (
                    <div className="flex flex-col gap-4 pt-2">
                      {(draft.trigger.kind === "interval" ||
                        draft.trigger.kind === "health") && (
                        <div className="flex flex-col gap-2">
                          <span className="flex items-center gap-1 text-sm font-medium">
                            {t("mxWindow")}
                            <HelpTip>{t("mxWindowHelp")}</HelpTip>
                          </span>
                          <div className="grid grid-cols-2 gap-3">
                            <Input
                              type="time"
                              dir="ltr"
                              aria-label={t("mxWindowFrom")}
                              value={from ?? ""}
                              onChange={(e) =>
                                setWindow(e.target.value, to ?? "")
                              }
                            />
                            <Input
                              type="time"
                              dir="ltr"
                              aria-label={t("mxWindowTo")}
                              value={to ?? ""}
                              onChange={(e) =>
                                setWindow(from ?? "", e.target.value)
                              }
                            />
                          </div>
                        </div>
                      )}
                      <div className="grid gap-4 sm:grid-cols-3">
                        <NumberField
                          id="plan-quiet"
                          label={t("mxQuietMbps")}
                          help={t("mxQuietHelp")}
                          min={0}
                          max={100000}
                          value={draft.guards.quiet_mbps ?? 0}
                          onChange={(quiet_mbps) =>
                            guards({
                              quiet_mbps,
                              quiet_wait: draft.guards.quiet_wait ?? 60,
                            })
                          }
                        />
                        {Boolean(draft.guards.quiet_mbps) && (
                          <>
                            <NumberField
                              id="plan-quiet-wait"
                              label={t("mxQuietWait")}
                              min={0}
                              max={360}
                              value={draft.guards.quiet_wait}
                              onChange={(quiet_wait) => guards({ quiet_wait })}
                            />
                            <Choice
                              id="plan-quiet-timeout"
                              label={t("mxQuietTimeout")}
                              value={draft.guards.quiet_timeout || "skip"}
                              onChange={(value) =>
                                guards({
                                  quiet_timeout: value as "run" | "skip",
                                })
                              }
                              choices={[
                                { value: "skip", label: t("quiet_skip") },
                                { value: "run", label: t("quiet_run") },
                              ]}
                            />
                          </>
                        )}
                      </div>
                      <div className="grid gap-4 sm:grid-cols-3">
                        <NumberField
                          id="plan-cooldown"
                          label={t("mxCooldown")}
                          help={t("mxCooldownHelp")}
                          min={0}
                          max={10080}
                          value={draft.guards.cooldown}
                          onChange={(cooldown) => guards({ cooldown })}
                        />
                        <NumberField
                          id="plan-max"
                          label={t("mxMaxPerDay")}
                          min={1}
                          max={48}
                          value={draft.guards.max_per_day}
                          onChange={(max_per_day) => guards({ max_per_day })}
                        />
                        <NumberField
                          id="plan-notice"
                          label={t("mxNotice")}
                          help={t("mxNoticeHelp")}
                          min={0}
                          max={60}
                          value={draft.guards.notice ?? 0}
                          onChange={(notice) => guards({ notice })}
                        />
                        {draft.action !== "reboot" ? (
                          <NumberField
                            id="plan-stagger"
                            label={t("mxStagger")}
                            help={t("mxStaggerHelp")}
                            min={0}
                            max={300}
                            value={draft.guards.stagger ?? 0}
                            onChange={(stagger) => guards({ stagger })}
                          />
                        ) : (
                          <NumberField
                            id="plan-min-uptime"
                            label={t("mxMinUptime")}
                            help={t("mxMinUptimeHelp")}
                            min={0}
                            max={1440}
                            value={draft.guards.min_uptime ?? 0}
                            onChange={(min_uptime) => guards({ min_uptime })}
                          />
                        )}
                      </div>
                    </div>
                  )}
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <label className="option-row">
                    <span className="flex flex-col gap-0.5">
                      <span className="text-sm font-medium">
                        {t("mxDryRun")}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {t("mxDryRunHelp")}
                      </span>
                    </span>
                    <Switch
                      checked={draft.dry_run}
                      onCheckedChange={(dry_run) => update({ dry_run })}
                    />
                  </label>
                  <label className="option-row">
                    <span className="text-sm font-medium">
                      {t("mxEnabled")}
                    </span>
                    <Switch
                      checked={draft.enabled}
                      onCheckedChange={(enabled) => update({ enabled })}
                    />
                  </label>
                </div>
                {kernelRestart && (
                  <Alert>
                    <TriangleAlert />
                    <AlertDescription>
                      {t("mxConntrackMissing")}
                    </AlertDescription>
                  </Alert>
                )}
                {tried && problem && (
                  <p className="text-sm text-destructive-text" role="alert">
                    {t(problem)}
                  </p>
                )}
              </form>
            </DialogBody>
            <DialogFooter layout="summary">
              <p className="min-w-0 text-xs text-muted-foreground">
                {risky && armed && !problem ? (
                  <span
                    className="font-medium text-destructive-text"
                    role="alert"
                  >
                    {t("mxRebootSaveConfirm")}
                  </span>
                ) : (
                  <>
                    <span className="font-medium text-foreground">
                      {t(`action_${draft.action}`)}
                    </span>
                    {" · "}
                    <bdi>{triggerSummary(cleanPlan(draft), t, dayName)}</bdi>
                  </>
                )}
              </p>
              <div className="flex gap-2">
                <Button variant="outline" disabled={busy} onClick={onClose}>
                  {t("cancel")}
                </Button>
                <Button
                  type="submit"
                  form="plan-editor"
                  disabled={busy}
                  variant={risky && armed ? "destructive" : "default"}
                >
                  {busy && (
                    <Loader2
                      data-icon="inline-start"
                      className="animate-spin"
                    />
                  )}
                  {t("mxSavePlan")}
                </Button>
              </div>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
