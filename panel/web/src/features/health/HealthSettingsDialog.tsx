import { useState } from "react";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import { EngineGlyph, TextField } from "@/components/shared";
import type { Connection } from "@/lib/api";
import { engineName } from "@/lib/format";
import { useT } from "@/lib/i18n";
import type { HealthSettings } from "@/features/operations/types";

type NumberSetting = Exclude<
  keyof HealthSettings,
  "enabled" | "failover" | "failover_interval"
>;

const limits: Record<
  NumberSetting,
  [min: number, max: number, label: string, help?: string]
> = {
  interval: [10, 300, "healthInterval", "healthIntervalHelp"],
  fail_threshold: [1, 10, "healthFail"],
  recover_threshold: [1, 10, "healthRecover"],
  latency_warn_ms: [0, 5000, "healthLatencyWarn", "healthLatencyWarnHelp"],
  retention_days: [1, 90, "healthRetention", "healthRetentionHelp"],
};

/** Kernel forwards that can fail over: enabled, two or more destinations. */
function failoverCandidates(connections: Connection[]) {
  return connections.filter(
    (c) =>
      (c.engine === "nftables" || c.engine === "iptables") &&
      c.enabled &&
      c.targets.length > 1,
  );
}

function healthSettingsValid(s: HealthSettings) {
  const interval = s.failover_interval;
  return (
    Number.isInteger(interval) &&
    interval >= 2 &&
    interval <= 30 &&
    (Object.keys(limits) as NumberSetting[]).every((key) => {
      const [min, max] = limits[key];
      const value = s[key];
      if (key === "latency_warn_ms" && value !== 0 && value < 20) return false;
      return Number.isInteger(value) && value >= min && value <= max;
    })
  );
}

export function HealthSettingsDialog({
  open,
  onOpenChange,
  settings,
  connections,
  save,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  settings: HealthSettings;
  connections: Connection[];
  save: (next: HealthSettings) => Promise<void>;
}) {
  const t = useT();
  const [draft, setDraft] = useState(settings);
  const candidates = failoverCandidates(connections);
  const selected = new Set(draft.failover);
  function choose(id: string, on: boolean) {
    const next = new Set(selected);
    if (on) next.add(id);
    else next.delete(id);
    // Keep the saved order stable and drop forwards that are no longer eligible.
    setDraft({
      ...draft,
      failover: candidates.map((c) => c.id).filter((x) => next.has(x)),
    });
  }
  const [busy, setBusy] = useState(false);
  const valid = healthSettingsValid(draft);
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) setDraft(settings);
        onOpenChange(next);
      }}
    >
      <DialogContent
        closeLabel={t("close")}
        scrollLayout="body"
        className="sm:max-w-xl"
      >
        <DialogHeader>
          <DialogTitle>{t("healthSettings")}</DialogTitle>
          <DialogDescription>{t("healthSettingsHelp")}</DialogDescription>
        </DialogHeader>
        <form
          id="health-settings"
          className="contents"
          onSubmit={(event) => {
            event.preventDefault();
            if (!valid) return;
            setBusy(true);
            save(draft)
              .then(() => onOpenChange(false))
              .catch(() => undefined)
              .finally(() => setBusy(false));
          }}
        >
          <DialogBody>
            <div className="grid gap-4 sm:grid-cols-2">
              {(Object.keys(limits) as NumberSetting[]).map((key) => {
                const [min, max, label, help] = limits[key];
                return (
                  <TextField
                    key={key}
                    id={`health-${key}`}
                    label={t(label)}
                    help={help ? t(help) : undefined}
                    type="number"
                    inputMode="numeric"
                    min={min}
                    max={max}
                    dir="ltr"
                    value={String(draft[key])}
                    aria-invalid={
                      !healthSettingsValid({ ...settings, [key]: draft[key] })
                    }
                    onChange={(event) =>
                      setDraft({ ...draft, [key]: Number(event.target.value) })
                    }
                  />
                );
              })}
            </div>
            <section
              className="failover-settings"
              aria-labelledby="failover-title"
            >
              <div className="flex flex-col gap-1">
                <h3 id="failover-title" className="text-sm font-semibold">
                  {t("healthFailoverSection")}
                </h3>
                <p className="text-xs leading-relaxed text-muted-foreground">
                  {t("healthFailoverHelp")}
                </p>
              </div>
              {candidates.length === 0 ? (
                <p className="rounded-lg border border-dashed p-4 text-center text-xs text-muted-foreground">
                  {t("healthFailoverNone")}
                </p>
              ) : (
                <>
                  <ul className="failover-list">
                    {candidates.map((c) => (
                      <li key={c.id}>
                        <label className="failover-item">
                          <span className="engine-icon">
                            <EngineGlyph engine={c.engine} />
                          </span>
                          <span className="flex min-w-0 flex-1 flex-col">
                            <span className="truncate text-sm font-medium">
                              <bdi>{c.name || c.id}</bdi>
                            </span>
                            <span className="text-xs text-muted-foreground">
                              {engineName(c.engine)} ·{" "}
                              {t("healthFailoverDestinations").replace(
                                "{n}",
                                String(c.targets.length),
                              )}
                            </span>
                          </span>
                          <Switch
                            checked={selected.has(c.id)}
                            onCheckedChange={(on) => choose(c.id, on)}
                          />
                        </label>
                      </li>
                    ))}
                  </ul>
                  <TextField
                    id="health-failover-interval"
                    label={t("healthFailoverInterval")}
                    help={t("healthFailoverIntervalHelp")}
                    type="number"
                    inputMode="numeric"
                    min={2}
                    max={30}
                    dir="ltr"
                    value={String(draft.failover_interval)}
                    aria-invalid={
                      !healthSettingsValid({
                        ...settings,
                        failover_interval: draft.failover_interval,
                      })
                    }
                    onChange={(event) =>
                      setDraft({
                        ...draft,
                        failover_interval: Number(event.target.value),
                      })
                    }
                  />
                </>
              )}
            </section>
          </DialogBody>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("cancel")}
          </Button>
          <Button
            type="submit"
            form="health-settings"
            disabled={!valid || busy}
          >
            {busy && (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            )}
            {t("save")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
