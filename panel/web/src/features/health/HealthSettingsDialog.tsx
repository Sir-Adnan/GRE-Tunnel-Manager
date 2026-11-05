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
import { TextField } from "@/components/shared";
import { useT } from "@/lib/i18n";
import type { HealthSettings } from "@/features/operations/types";

const limits: Record<
  Exclude<keyof HealthSettings, "enabled">,
  [min: number, max: number, label: string, help?: string]
> = {
  interval: [10, 300, "healthInterval", "healthIntervalHelp"],
  fail_threshold: [1, 10, "healthFail"],
  recover_threshold: [1, 10, "healthRecover"],
  latency_warn_ms: [0, 5000, "healthLatencyWarn", "healthLatencyWarnHelp"],
  retention_days: [1, 90, "healthRetention", "healthRetentionHelp"],
};

function healthSettingsValid(s: HealthSettings) {
  return (Object.keys(limits) as (keyof typeof limits)[]).every((key) => {
    const [min, max] = limits[key];
    const value = s[key];
    if (key === "latency_warn_ms" && value !== 0 && value < 20) return false;
    return Number.isInteger(value) && value >= min && value <= max;
  });
}

export function HealthSettingsDialog({
  open,
  onOpenChange,
  settings,
  save,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  settings: HealthSettings;
  save: (next: HealthSettings) => Promise<void>;
}) {
  const t = useT();
  const [draft, setDraft] = useState(settings);
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
        className="sm:max-w-lg"
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
              {(Object.keys(limits) as (keyof typeof limits)[]).map((key) => {
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
