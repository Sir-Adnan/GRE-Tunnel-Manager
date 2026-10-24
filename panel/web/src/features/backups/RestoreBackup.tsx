import { useContext, useState } from "react";
import {
  ArrowRight,
  Check,
  FileKey2,
  Loader2,
  RotateCcw,
  Server,
} from "lucide-react";
import { api, operate } from "@/lib/api";
import { LocaleContext, useT } from "@/lib/i18n";
import type { Inventory } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Field,
  FieldLabel,
  FieldGroup,
  FieldContent,
} from "@/components/ui/field";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogBody,
  DialogFooter,
} from "@/components/ui/dialog";
import { MigrationFields } from "./MigrationFields";
import { TextField } from "@/components/shared";
import { maxBackupBytes, migrationValues } from "./contract";
import type { BackupReview, BackupInput } from "./contract";

export function RestoreBackup({
  inventory,
  refreshed,
}: {
  inventory: Inventory;
  refreshed: () => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [archive, setArchive] = useState("");
  const [filename, setFilename] = useState("");
  const [password, setPassword] = useState("");
  const [traffic, setTraffic] = useState(true);
  const [addresses, setAddresses] = useState<Record<string, string>>({});
  const [interfaces, setInterfaces] = useState<Record<string, string>>({});
  const [review, setReview] = useState<BackupReview>();
  const [reviewed, setReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [confirm, setConfirm] = useState(false);
  const [finished, setFinished] = useState(false);
  const [warning, setWarning] = useState("");
  const input = (): BackupInput => ({
    archive,
    password,
    include_traffic: traffic,
    addresses: migrationValues(addresses),
    interfaces: migrationValues(interfaces),
    revision: review?.revision,
  });
  const reset = () => {
    setArchive("");
    setFilename("");
    setPassword("");
    setReview(undefined);
    setReviewed(false);
    setAddresses({});
    setInterfaces({});
    setError("");
    setFinished(false);
    setWarning("");
  };
  if (finished)
    return (
      <div className="flex flex-col items-start gap-4 py-4">
        <span className="flex size-10 items-center justify-center rounded-full bg-secondary">
          <Check className="size-5" />
        </span>
        <h2 className="text-lg font-medium">{t("backupRestored")}</h2>
        <p className="max-w-prose text-sm text-muted-foreground">
          {t("backupNextSteps")}
        </p>
        {warning && (
          <Alert>
            <AlertDescription>{t(warning)}</AlertDescription>
          </Alert>
        )}
        <Button variant="outline" onClick={reset}>
          {t("backupChooseAnother")}
        </Button>
      </div>
    );
  return (
    <div className="flex flex-col gap-6">
      {!review ? (
        <form
          className="flex flex-col gap-5"
          onSubmit={async (event) => {
            event.preventDefault();
            setBusy(true);
            setError("");
            try {
              const next = await api<BackupReview>("backups/review", input());
              setReview(next);
              setReviewed(true);
            } catch (e) {
              setError(e instanceof Error ? e.message : String(e));
            } finally {
              setBusy(false);
            }
          }}
        >
          <div className="flex items-start gap-3">
            <FileKey2 className="mt-1 size-5 shrink-0 text-primary" />
            <div className="flex flex-col gap-1">
              <h2 className="text-base font-medium">{t("backupRestore")}</h2>
              <p className="max-w-prose text-sm text-muted-foreground">
                {t("backupRestoreHelp")}
              </p>
            </div>
          </div>
          <FieldGroup columns>
            <Field>
              <FieldLabel htmlFor="recovery-file">{t("backupFile")}</FieldLabel>
              <Input
                id="recovery-file"
                type="file"
                accept=".gtm-backup,application/json"
                disabled={busy}
                required
                onChange={async (e) => {
                  const file = e.target.files?.[0];
                  reset();
                  if (!file) return;
                  if (file.size > maxBackupBytes) {
                    setError(t("backupFileLarge"));
                    e.target.value = "";
                    return;
                  }
                  setBusy(true);
                  try {
                    const content = await file.text();
                    JSON.parse(content);
                    setArchive(content);
                    setFilename(file.name);
                  } catch {
                    setError(t("backupInvalidFile"));
                    e.target.value = "";
                  } finally {
                    setBusy(false);
                  }
                }}
              />
            </Field>
            <TextField
              id="recovery-password"
              label={t("backupPassword")}
              type="password"
              autoComplete="off"
              required
              minLength={8}
              maxLength={256}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={busy}
            />
          </FieldGroup>
          <div className="flex justify-end">
            <Button type="submit" disabled={busy || !archive}>
              {busy ? (
                <Loader2 data-icon="inline-start" className="animate-spin" />
              ) : (
                <FileKey2 data-icon="inline-start" />
              )}
              {t("backupInspect")}
            </Button>
          </div>
        </form>
      ) : (
        <>
          <div className="grid min-w-0 gap-4 rounded-xl border bg-muted/20 p-4 sm:grid-cols-[1fr_auto_1fr] sm:items-center">
            <div className="min-w-0">
              <p className="text-xs text-muted-foreground">
                {t("backupSource")}
              </p>
              <p className="truncate font-medium" dir="auto">
                {review.host}
              </p>
              <p className="text-xs text-muted-foreground">
                {new Intl.DateTimeFormat(
                  locale === "fa" ? "fa-IR-u-nu-latn" : "en-US",
                  { dateStyle: "medium", timeStyle: "short" },
                ).format(new Date(review.created))}
              </p>
            </div>
            <ArrowRight className="size-4 rotate-90 text-muted-foreground sm:rotate-0 sm:rtl:rotate-180" />
            <div className="min-w-0">
              <p className="text-xs text-muted-foreground">
                {t("backupDestination")}
              </p>
              <p className="truncate font-medium" dir="auto">
                {inventory.host.hostname}
              </p>
              <p className="text-xs text-muted-foreground">
                {t("backupPaused")}
              </p>
            </div>
          </div>
          <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
            <div className="flex min-w-0 items-center gap-2">
              <FileKey2 className="size-4 shrink-0" />
              <span className="truncate text-xs" dir="auto">
                {filename}
              </span>
              <Badge variant="outline">
                <bdi>v{review.version}</bdi>
              </Badge>
            </div>
            <Button size="sm" variant="ghost" disabled={busy} onClick={reset}>
              {t("backupChooseAnother")}
            </Button>
          </div>
          <MigrationFields
            review={review}
            addresses={addresses}
            interfaces={interfaces}
            disabled={busy}
            onAddressChange={(from, to) => {
              setAddresses({ ...addresses, [from]: to });
              setReviewed(false);
            }}
            onInterfaceChange={(from, to) => {
              setInterfaces({ ...interfaces, [from]: to });
              setReviewed(false);
            }}
          />
          {review.traffic && (
            <Field orientation="horizontal" className="rounded-lg border p-3">
              <FieldContent>
                <FieldLabel htmlFor="restore-traffic">
                  {t("backupIncludeTraffic")}
                </FieldLabel>
              </FieldContent>
              <Switch
                id="restore-traffic"
                checked={traffic}
                disabled={busy}
                onCheckedChange={(v) => {
                  setTraffic(v);
                  setReviewed(false);
                }}
              />
            </Field>
          )}
          <details className="rounded-lg border p-3">
            <summary className="cursor-pointer font-medium">
              {t("backupContents")} <bdi>({review.items.length})</bdi>
            </summary>
            <ul className="mt-3 flex max-h-56 flex-col gap-2 overflow-y-auto">
              {review.items.map((item) => (
                <li
                  key={item.id}
                  className="flex min-w-0 items-center justify-between gap-3 text-sm"
                >
                  <div className="flex min-w-0 flex-col gap-1">
                    <span className="truncate" dir="auto">
                      {item.name}
                    </span>
                    <code
                      className="break-all text-xs text-muted-foreground"
                      dir="ltr"
                    >
                      {item.summary}
                    </code>
                  </div>
                  <Badge variant="outline">{item.engine}</Badge>
                </li>
              ))}
            </ul>
          </details>
          {review.certificates.length > 0 && (
            <Alert>
              <AlertDescription>
                <p>{t("backupCertificates")}</p>
                {review.certificates.map((path) => (
                  <code
                    key={path}
                    dir="ltr"
                    className="block break-all text-xs"
                  >
                    {path}
                  </code>
                ))}
              </AlertDescription>
            </Alert>
          )}
          {review.blockers.map((key) => (
            <Alert variant="destructive" key={key}>
              <AlertDescription>{t(key)}</AlertDescription>
            </Alert>
          ))}
          <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
            <span className="flex items-center gap-2 text-xs text-muted-foreground">
              <Server className="size-4" />
              {t("backupPaused")}
            </span>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  setError("");
                  try {
                    setReview(
                      await api<BackupReview>("backups/review", input()),
                    );
                    setReviewed(true);
                  } catch (e) {
                    setReviewed(false);
                    setError(e instanceof Error ? e.message : String(e));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {busy ? (
                  <Loader2 className="animate-spin" data-icon="inline-start" />
                ) : (
                  <RotateCcw data-icon="inline-start" />
                )}
                {t("backupReview")}
              </Button>
              <Button
                disabled={busy || !reviewed || review.blockers.length > 0}
                onClick={() => setConfirm(true)}
              >
                {t("backupRestoreAction")}
              </Button>
            </div>
          </div>
        </>
      )}
      {error && (
        <Alert variant="destructive" role="alert">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <Dialog
        open={confirm}
        onOpenChange={(open) => {
          if (!busy) setConfirm(open);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("backupConfirmRestore")}</DialogTitle>
            <DialogDescription>{t("backupConfirmHelp")}</DialogDescription>
          </DialogHeader>
          <DialogBody>
            <p className="text-sm">
              {t("backupDestination")}: <bdi>{inventory.host.hostname}</bdi>
            </p>
            <p className="mt-2 text-sm">
              {t("backupContents")}: <bdi>{review?.items.length}</bdi>
            </p>
          </DialogBody>
          <DialogFooter>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setConfirm(false)}
            >
              {t("cancel")}
            </Button>
            <Button
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                setError("");
                try {
                  const job = await operate(
                    input(),
                    undefined,
                    "backups/restore",
                  );
                  const result = job.result as { warning?: string };
                  setWarning(result?.warning || "");
                  setFinished(true);
                  setConfirm(false);
                  setArchive("");
                  setPassword("");
                  try {
                    await refreshed();
                  } catch {
                    setWarning("savedRefreshFailed");
                  }
                } catch (e) {
                  setConfirm(false);
                  setReviewed(false);
                  setError(e instanceof Error ? e.message : String(e));
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy && (
                <Loader2 className="animate-spin" data-icon="inline-start" />
              )}
              {t(busy ? "working" : "backupRestoreAction")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
