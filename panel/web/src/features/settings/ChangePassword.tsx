// Account password: changed from a signed-in browser through the broker,
// which checks the current password (and the two-factor code). The panel
// keeps running; other browsers are signed out. SSH stays the recovery path.
import { useState } from "react";
import { toast } from "sonner";
import { KeyRound, Loader2 } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
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
import { FieldGroup } from "@/components/ui/field";
import { TextField } from "@/components/shared";
import { api } from "@/lib/api";
import { passwordCommand } from "@/lib/commands";
import { errorMessage, useT } from "@/lib/i18n";
import { passwordIssue, passwordStrength } from "./password";

export function ChangePassword({
  twoFactor,
  done,
}: {
  twoFactor: boolean;
  done: () => void;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  return (
    <section className="flex flex-col gap-3" aria-labelledby="password-title">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex min-w-0 flex-col gap-1">
          <h3
            id="password-title"
            className="flex items-center gap-2 text-sm font-medium"
          >
            <KeyRound aria-hidden className="size-4" />
            {t("passwordTitle")}
          </h3>
          <p className="text-sm text-muted-foreground">{t("passwordIntro")}</p>
        </div>
        <Button variant="outline" onClick={() => setOpen(true)}>
          {t("passwordChange")}
        </Button>
      </div>
      <p className="text-xs leading-6 text-muted-foreground">
        {t("passwordForgot")
          .split(passwordCommand)
          .map((part, i) => (
            <span key={i}>
              {i > 0 && (
                <code dir="ltr" className="rounded bg-muted px-1.5 py-0.5">
                  {passwordCommand}
                </code>
              )}
              {part}
            </span>
          ))}
      </p>
      <PasswordDialog
        open={open}
        twoFactor={twoFactor}
        onClose={() => setOpen(false)}
        done={done}
      />
    </section>
  );
}

function PasswordDialog({
  open,
  twoFactor,
  onClose,
  done,
}: {
  open: boolean;
  twoFactor: boolean;
  onClose: () => void;
  done: () => void;
}) {
  const t = useT();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [code, setCode] = useState("");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const issue = passwordIssue(current, next, repeat);
  const strength = passwordStrength(next);
  function close() {
    setCurrent("");
    setNext("");
    setRepeat("");
    setCode("");
    setTouched(false);
    setFailure("");
    onClose();
  }
  async function submit() {
    setTouched(true);
    if (issue || !current || (twoFactor && !code.trim())) return;
    setBusy(true);
    setFailure("");
    try {
      const result = await api<{ signed_out: number }>("security/password", {
        current,
        next,
        code: code.trim(),
      });
      toast.success(
        result.signed_out
          ? t("passwordChangedOthers").replace("{n}", String(result.signed_out))
          : t("passwordChanged"),
      );
      done();
      close();
    } catch (e) {
      setFailure(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }
  const show = (field: "next" | "repeat") =>
    touched && issue && issue.field === field ? t(issue.key) : undefined;
  return (
    <Dialog open={open} onOpenChange={(value) => !value && !busy && close()}>
      <DialogContent closeLabel={t("close")} className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("passwordChange")}</DialogTitle>
          <DialogDescription>{t("passwordIntro")}</DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form
            id="password-change"
            noValidate
            onSubmit={(event) => {
              event.preventDefault();
              void submit();
            }}
          >
            <FieldGroup>
              <TextField
                id="password-current"
                label={t("passwordCurrent")}
                type="password"
                autoComplete="current-password"
                value={current}
                disabled={busy}
                maxLength={72}
                error={touched && !current ? t("passwordEnter") : undefined}
                onChange={(e) => setCurrent(e.target.value)}
              />
              <div className="flex flex-col gap-2">
                <TextField
                  id="password-new"
                  label={t("passwordNew")}
                  type="password"
                  autoComplete="new-password"
                  value={next}
                  disabled={busy}
                  maxLength={72}
                  description={t("passwordNewHelp")}
                  error={show("next")}
                  onChange={(e) => setNext(e.target.value)}
                />
                {next && (
                  <div
                    className="password-meter"
                    data-strength={strength}
                    aria-live="polite"
                  >
                    <span aria-hidden>
                      <i />
                      <i />
                      <i />
                    </span>
                    {t(`passwordStrength_${strength}`)}
                  </div>
                )}
              </div>
              <TextField
                id="password-repeat"
                label={t("passwordConfirm")}
                type="password"
                autoComplete="new-password"
                value={repeat}
                disabled={busy}
                maxLength={72}
                error={show("repeat")}
                onChange={(e) => setRepeat(e.target.value)}
              />
              {twoFactor && (
                <TextField
                  id="password-code"
                  label={t("twoFactorCodeOrRecovery")}
                  dir="ltr"
                  autoComplete="one-time-code"
                  className="font-mono"
                  value={code}
                  disabled={busy}
                  maxLength={32}
                  error={
                    touched && !code.trim() ? t("passwordEnter") : undefined
                  }
                  onChange={(e) => setCode(e.target.value)}
                />
              )}
            </FieldGroup>
          </form>
          {failure && (
            <Alert variant="destructive" role="alert" className="mt-4">
              <AlertDescription>{failure}</AlertDescription>
            </Alert>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={close}>
            {t("cancel")}
          </Button>
          <Button type="submit" form="password-change" disabled={busy}>
            {busy && (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            )}
            {t("passwordChange")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
