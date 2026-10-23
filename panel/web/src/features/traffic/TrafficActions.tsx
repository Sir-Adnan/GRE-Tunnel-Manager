import { useState } from "react";
import { RotateCcw, SlidersHorizontal, Square, Trash2 } from "lucide-react";
import { CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogContent,
  DialogFooter,
} from "@/components/ui/dialog";
import { Choice, TextField } from "@/components/shared";
import type { Connection, TrafficPolicy } from "@/lib/api";
import { useT } from "@/lib/i18n";

// Capture identity and revision when a dialog opens; a refresh cannot retarget it.
export function TrafficActions({
  id,
  name,
  connection,
  removed,
  policy,
  revision,
  disabled,
  run,
  refresh,
}: {
  id: string;
  name: string;
  connection?: Connection;
  removed: boolean;
  policy?: TrafficPolicy;
  revision?: number;
  disabled: boolean;
  run: (r: unknown) => Promise<void>;
  refresh: () => Promise<void>;
}) {
  const t = useT();
  const [editing, setEditing] = useState(false),
    [confirm, setConfirm] = useState("");
  const [working, setWorking] = useState(false),
    [error, setError] = useState("");
  const [draft, setDraft] = useState<TrafficPolicy>({
    label: "",
    limit: 0,
    direction: "total",
  });
  const [gib, setGiB] = useState("0");
  const [target, setTarget] = useState<{
    id: string;
    title: string;
    revision: number;
    selection?: { id: string; revision: string };
  }>();
  const p = policy,
    locked = disabled || working || revision === undefined;
  function captureTarget() {
    if (revision !== undefined)
      setTarget({
        id,
        title: name,
        revision,
        selection: connection
          ? { id: connection.id, revision: connection.revision }
          : undefined,
      });
  }
  function openConfirm(action: string) {
    captureTarget();
    setError("");
    setConfirm(action);
  }
  async function act(action: string) {
    if (!target) return;
    setWorking(true);
    setError("");
    try {
      await run({
        action,
        traffic: { id: target.id, revision: target.revision, policy: draft },
        ...(action === "disable" && target.selection
          ? { selected: [target.selection] }
          : {}),
      });
      await refresh();
      setConfirm("");
      setEditing(false);
    } catch (e) {
      setError(String(e));
    } finally {
      setWorking(false);
    }
  }
  return (
    <>
      {error && !editing && !confirm && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <CardFooter className="flex flex-wrap gap-2">
        <Button
          variant="outline"
          disabled={locked}
          onClick={() => {
            captureTarget();
            setError("");
            setDraft(p || { label: "", limit: 0, direction: "total" });
            setGiB(String((p?.limit || 0) / 1024 ** 3));
            setEditing(true);
          }}
        >
          <SlidersHorizontal data-icon="inline-start" />
          {t("customerQuota")}
        </Button>
        <Button
          variant="outline"
          disabled={locked}
          onClick={() => openConfirm("metrics-reset")}
        >
          <RotateCcw data-icon="inline-start" />
          {t("resetUsage")}
        </Button>
        {connection?.enabled && (
          <Button
            variant="outline"
            disabled={locked}
            onClick={() => openConfirm("disable")}
          >
            <Square data-icon="inline-start" />
            {t("disable")}
          </Button>
        )}
        {removed && (
          <Button
            variant="outline"
            disabled={locked}
            onClick={() => openConfirm("metrics-forget")}
          >
            <Trash2 data-icon="inline-start" />
            {t("forgetAccounting")}
          </Button>
        )}
      </CardFooter>
      <Dialog
        open={editing}
        onOpenChange={(open) => !working && setEditing(open)}
      >
        <DialogContent closeLabel={t("close")}>
          <DialogHeader>
            <DialogTitle>{t("customerQuota")}</DialogTitle>
            <DialogDescription>{t("quotaDialogHelp")}</DialogDescription>
          </DialogHeader>
          <form
            id="quota-form"
            className="flex flex-col gap-5"
            onSubmit={(e) => {
              e.preventDefault();
              void act("metrics-policy");
            }}
          >
            <TextField
              id="customer-label"
              label={t("customerLabel")}
              value={draft.label}
              maxLength={80}
              onChange={(e) => setDraft({ ...draft, label: e.target.value })}
            />
            <TextField
              id="quota-gib"
              label={t("quotaGiB")}
              help={t("quotaHelp")}
              type="number"
              min={0}
              max={8388607}
              step="0.001"
              required
              value={gib}
              onChange={(e) => {
                setGiB(e.target.value);
                setDraft({
                  ...draft,
                  limit: Math.round(Number(e.target.value) * 1024 ** 3),
                });
              }}
            />
            <Choice
              id="quota-direction"
              label={t("quotaDirection")}
              value={draft.direction}
              onChange={(v) =>
                setDraft({
                  ...draft,
                  direction: v as TrafficPolicy["direction"],
                })
              }
              choices={["total", "received", "sent"].map((v) => ({
                value: v,
                label: t(v),
              }))}
            />
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
          </form>
          <DialogFooter>
            <Button
              variant="outline"
              disabled={working}
              onClick={() => setEditing(false)}
            >
              {t("cancel")}
            </Button>
            <Button
              form="quota-form"
              type="submit"
              disabled={
                working || !Number.isFinite(draft.limit) || draft.limit < 0
              }
            >
              {t(working ? "working" : "save")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog
        open={Boolean(confirm)}
        onOpenChange={(open) => !open && !working && setConfirm("")}
      >
        <DialogContent closeLabel={t("close")}>
          <DialogHeader>
            <DialogTitle>
              {t(
                confirm === "metrics-reset"
                  ? "resetUsage"
                  : confirm === "disable"
                    ? "disable"
                    : "forgetAccounting",
              )}{" "}
              · {target?.title}
            </DialogTitle>
            <DialogDescription>
              {t(
                confirm === "metrics-reset"
                  ? "resetUsageHelp"
                  : confirm === "disable"
                    ? "disableQuotaHelp"
                    : "forgetAccountingHelp",
              )}
            </DialogDescription>
          </DialogHeader>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button
              variant="outline"
              disabled={working}
              onClick={() => setConfirm("")}
            >
              {t("cancel")}
            </Button>
            <Button
              variant="destructive"
              disabled={working}
              onClick={() => void act(confirm)}
            >
              {t(working ? "working" : "confirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
