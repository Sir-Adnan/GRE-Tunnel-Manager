import { useState } from "react";
import { Download, LockKeyhole, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { Button } from "@/components/ui/button";
import { TextField } from "@/components/shared";
import {
  Field,
  FieldContent,
  FieldLabel,
  FieldGroup,
} from "@/components/ui/field";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { HelpTip } from "@/components/help";
import { downloadBackup } from "./contract";

export function CreateBackup() {
  const t = useT();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [traffic, setTraffic] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <form
      className="flex flex-col gap-6"
      onSubmit={async (event) => {
        event.preventDefault();
        if (password !== confirm) {
          setError(t("backupPasswordMismatch"));
          return;
        }
        setBusy(true);
        setError("");
        try {
          const file = await api<{ filename: string; archive: string }>(
            "backups/export",
            { password, include_traffic: traffic },
          );
          downloadBackup(file.filename, file.archive);
          setPassword("");
          setConfirm("");
          toast.success(t("backupDownloaded"));
        } catch (e) {
          setError(e instanceof Error ? e.message : String(e));
        } finally {
          setBusy(false);
        }
      }}
    >
      <div className="flex items-start gap-3">
        <LockKeyhole className="mt-1 size-5 shrink-0 text-primary" />
        <div className="flex flex-col gap-1">
          <h2 className="text-base font-medium">{t("backupCreate")}</h2>
          <p className="max-w-prose text-sm text-muted-foreground">
            {t("backupCreateHelp")}
          </p>
        </div>
      </div>
      <FieldGroup columns>
        <TextField
          id="backup-password"
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
          id="backup-password-confirm"
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
      </FieldGroup>
      <Field orientation="horizontal" className="rounded-lg border p-4">
        <FieldContent>
          <div className="flex items-center gap-2">
            <FieldLabel htmlFor="backup-traffic">
              {t("backupIncludeTraffic")}
            </FieldLabel>
            <HelpTip label={t("backupIncludeTraffic")}>
              {t("backupTrafficHelp")}
            </HelpTip>
          </div>
        </FieldContent>
        <Switch
          id="backup-traffic"
          checked={traffic}
          onCheckedChange={setTraffic}
          disabled={busy}
        />
      </Field>
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
        <p className="max-w-sm text-xs text-muted-foreground">
          {t("backupPasswordKeep")}
        </p>
        <Button type="submit" disabled={busy}>
          {busy ? (
            <Loader2 className="animate-spin" data-icon="inline-start" />
          ) : (
            <Download data-icon="inline-start" />
          )}
          {t(busy ? "working" : "backupDownload")}
        </Button>
      </div>
    </form>
  );
}
