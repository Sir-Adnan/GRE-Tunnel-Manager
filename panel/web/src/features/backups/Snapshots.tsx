import { useContext, useEffect, useState } from "react";
import {
  CalendarClock,
  Download,
  HardDrive,
  Loader2,
  Play,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { TextField } from "@/components/shared";
import { api } from "@/lib/api";
import { number, trafficBytes } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import { useLoaded } from "@/features/operations/hooks";
import { stamp } from "@/features/health/format";
import { Confirm, type ConfirmRequest } from "@/features/maintenance/Confirm";
import { downloadBackup } from "./contract";

type SnapshotSettings = {
  enabled: boolean;
  frequency: "daily" | "weekly";
  time: string;
  weekday: number;
  keep: number;
  traffic: boolean;
};

type SnapshotInfo = {
  name: string;
  created: string;
  size: number;
  connections: number;
  resources: number;
  traffic: boolean;
};

type SnapshotView = {
  settings: SnapshotSettings;
  revision: number;
  timezone: string;
  next?: string;
  last?: string;
  last_error?: string;
  snapshots: SnapshotInfo[];
};

/** Seals one local snapshot with a password and downloads it. */
function DownloadDialog({
  snapshot,
  onClose,
}: {
  snapshot?: SnapshotInfo;
  onClose: () => void;
}) {
  const t = useT();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <Dialog open={Boolean(snapshot)} onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent closeLabel={t("close")} className="sm:max-w-md">
        <form
          className="flex flex-col gap-4"
          onSubmit={async (event) => {
            event.preventDefault();
            if (!snapshot) return;
            if (password !== confirm) {
              setError(t("backupPasswordMismatch"));
              return;
            }
            setBusy(true);
            setError("");
            try {
              const file = await api<{ filename: string; archive: string }>(
                "backups/snapshot",
                { password, snapshot: snapshot.name, include_traffic: false },
              );
              downloadBackup(file.filename, file.archive);
              toast.success(t("backupDownloaded"));
              onClose();
            } catch (e) {
              setError(e instanceof Error ? e.message : String(e));
            } finally {
              setBusy(false);
            }
          }}
        >
          <DialogHeader>
            <DialogTitle>{t("snapDownloadTitle")}</DialogTitle>
            <DialogDescription>{t("snapDownloadBody")}</DialogDescription>
          </DialogHeader>
          <TextField
            id="snap-password"
            label={t("backupPassword")}
            type="password"
            autoComplete="new-password"
            required
            minLength={8}
            maxLength={256}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={busy}
          />
          <TextField
            id="snap-password-confirm"
            label={t("backupConfirmPassword")}
            type="password"
            autoComplete="new-password"
            required
            minLength={8}
            maxLength={256}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            disabled={busy}
          />
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
              {t("cancel")}
            </Button>
            <Button type="submit" disabled={busy}>
              {busy ? (
                <Loader2 className="animate-spin" data-icon="inline-start" />
              ) : (
                <Download data-icon="inline-start" />
              )}
              {t("snapDownload")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

const weekdays = [0, 1, 2, 3, 4, 5, 6];

/** Scheduled local snapshots: schedule, list, download and delete. */
export function Snapshots({ run }: { run: (request: unknown) => Promise<void> }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { value, error, reload } = useLoaded<SnapshotView>("snapshots", () => 60);
  const [draft, setDraft] = useState<SnapshotSettings>();
  const [busy, setBusy] = useState(false);
  const [download, setDownload] = useState<SnapshotInfo>();
  const [confirm, setConfirm] = useState<ConfirmRequest>();
  const revision = value?.revision;
  useEffect(() => {
    if (value) setDraft(value.settings);
    // Reset the form only when the stored schedule changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revision]);
  async function act(request: unknown) {
    setBusy(true);
    try {
      await run(request);
    } catch {
      // The operation dialog shows the error.
    } finally {
      setBusy(false);
      await reload();
    }
  }
  if (!value || !draft)
    return error ? (
      <Alert variant="destructive">
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    ) : (
      <Skeleton className="h-64 w-full" />
    );
  const set = (patch: Partial<SnapshotSettings>) => setDraft({ ...draft, ...patch });
  const dayName = (d: number) =>
    new Date(Date.UTC(2024, 0, 7 + d)).toLocaleDateString(
      locale === "fa" ? "fa-IR-u-nu-latn" : "en",
      { weekday: "long", timeZone: "UTC" },
    );
  const changed = JSON.stringify(draft) !== JSON.stringify(value.settings);
  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-start gap-3">
        <CalendarClock className="mt-1 size-5 shrink-0 text-primary" aria-hidden />
        <div className="flex flex-col gap-1">
          <h2 className="text-base font-medium">{t("snapTitle")}</h2>
          <p className="max-w-prose text-sm text-muted-foreground">{t("snapIntro")}</p>
        </div>
      </div>
      <dl className="snap-status">
        <div>
          <dt>{t("snapNext")}</dt>
          <dd>{value.settings.enabled && value.next ? stamp(value.next, locale, value.timezone) : t("snapOff")}</dd>
        </div>
        <div>
          <dt>{t("snapLast")}</dt>
          <dd>{value.last ? stamp(value.last, locale, value.timezone) : "—"}</dd>
        </div>
        <div>
          <dt>{t("snapStored")}</dt>
          <dd>{number(value.snapshots.length, locale)} / {number(value.settings.keep, locale)}</dd>
        </div>
      </dl>
      {value.last_error && (
        <Alert variant="destructive">
          <AlertDescription>{t("snapLastError").replace("{e}", value.last_error)}</AlertDescription>
        </Alert>
      )}
      <form
        className="flex flex-col gap-5 rounded-lg border p-4"
        onSubmit={(e) => {
          e.preventDefault();
          void act({ action: "snapshots-configure", snapshot: { settings: draft, revision: value.revision } });
        }}
      >
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="snap-enabled">{t("snapEnable")}</FieldLabel>
            <FieldDescription>{t("snapEnableHelp").replace("{zone}", value.timezone)}</FieldDescription>
          </FieldContent>
          <Switch id="snap-enabled" checked={draft.enabled} disabled={busy} onCheckedChange={(enabled) => set({ enabled })} />
        </Field>
        <FieldGroup columns>
          <Field>
            <FieldLabel>{t("snapFrequency")}</FieldLabel>
            <ToggleGroup
              type="single"
              variant="outline"
              value={draft.frequency}
              onValueChange={(v) => v && set({ frequency: v as "daily" | "weekly" })}
              disabled={busy || !draft.enabled}
            >
              <ToggleGroupItem value="daily">{t("snapDaily")}</ToggleGroupItem>
              <ToggleGroupItem value="weekly">{t("snapWeekly")}</ToggleGroupItem>
            </ToggleGroup>
          </Field>
          {draft.frequency === "weekly" && (
            <Field>
              <FieldLabel htmlFor="snap-weekday">{t("snapWeekday")}</FieldLabel>
              <NativeSelect
                id="snap-weekday"
                value={String(draft.weekday)}
                disabled={busy || !draft.enabled}
                onChange={(e) => set({ weekday: Number(e.target.value) })}
              >
                {weekdays.map((d) => (
                  <NativeSelectOption key={d} value={String(d)}>
                    {dayName(d)}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            </Field>
          )}
          <Field>
            <FieldLabel htmlFor="snap-time">{t("snapTime")}</FieldLabel>
            <Input
              id="snap-time"
              type="time"
              dir="ltr"
              required
              value={draft.time}
              disabled={busy || !draft.enabled}
              onChange={(e) => set({ time: e.target.value })}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="snap-keep">{t("snapKeep")}</FieldLabel>
            <Input
              id="snap-keep"
              type="number"
              dir="ltr"
              min={1}
              max={60}
              required
              value={draft.keep}
              disabled={busy}
              onChange={(e) => set({ keep: Number(e.target.value) })}
            />
          </Field>
        </FieldGroup>
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="snap-traffic">{t("backupIncludeTraffic")}</FieldLabel>
            <FieldDescription>{t("backupTrafficHelp")}</FieldDescription>
          </FieldContent>
          <Switch id="snap-traffic" checked={draft.traffic} disabled={busy} onCheckedChange={(traffic) => set({ traffic })} />
        </Field>
        <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
          <p className="max-w-sm text-xs text-muted-foreground">{t("snapPrivacy")}</p>
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" disabled={busy} onClick={() => void act({ action: "snapshots-run" })}>
              <Play data-icon="inline-start" />
              {t("snapRunNow")}
            </Button>
            <Button type="submit" disabled={busy || !changed}>
              {busy && <Loader2 className="animate-spin" data-icon="inline-start" />}
              {t("snapSave")}
            </Button>
          </div>
        </div>
      </form>
      <section className="flex flex-col gap-3" aria-label={t("snapList")}>
        <h3 className="text-sm font-medium">{t("snapList")}</h3>
        {value.snapshots.length === 0 ? (
          <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">{t("snapEmpty")}</p>
        ) : (
          <ul className="snap-list">
            {value.snapshots.map((s) => (
              <li key={s.name}>
                <HardDrive className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                <div className="flex min-w-0 flex-1 flex-col">
                  <span className="text-sm font-medium">{stamp(s.created || s.name, locale, value.timezone)}</span>
                  <span className="text-xs text-muted-foreground">
                    {t("snapItem")
                      .replace("{c}", number(s.connections, locale))
                      .replace("{r}", number(s.resources, locale))
                      .replace("{size}", trafficBytes(s.size, locale))}
                  </span>
                </div>
                <Button variant="ghost" size="sm" onClick={() => setDownload(s)}>
                  <Download data-icon="inline-start" />
                  <span className="hidden sm:inline">{t("snapDownload")}</span>
                </Button>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={`${t("delete")} ${s.name}`}
                  disabled={busy}
                  onClick={() =>
                    setConfirm({
                      title: t("snapDeleteTitle"),
                      body: t("snapDeleteBody"),
                      action: t("delete"),
                      destructive: true,
                      run: () => act({ action: "snapshots-delete", snapshot: { name: s.name } }),
                    })
                  }
                >
                  <Trash2 />
                </Button>
              </li>
            ))}
          </ul>
        )}
      </section>
      <DownloadDialog key={download?.name ?? ""} snapshot={download} onClose={() => setDownload(undefined)} />
      <Confirm request={confirm} onClose={() => setConfirm(undefined)} />
    </div>
  );
}
