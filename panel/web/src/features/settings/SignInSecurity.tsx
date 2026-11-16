import { useContext, useEffect, useState } from "react";
import { toast } from "sonner";
import {
  Download,
  KeyRound,
  Loader2,
  LogOut,
  MonitorSmartphone,
  ShieldCheck,
  ShieldOff,
} from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
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
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { CommandBlock } from "@/components/CommandBlock";
import { CopyButton } from "@/components/CopyButton";
import { useLoaded } from "@/features/operations/hooks";
import { api } from "@/lib/api";
import { errorMessage, LocaleContext, useT } from "@/lib/i18n";
import {
  describeAgent,
  groupSecret,
  qrPath,
  sixDigits,
  type SecurityView,
  type TwoFactorSetup,
} from "./sessions";

/** Two-factor sign-in, signed-in browsers and the account password. */
export function SignInSecurity({ logout }: { logout: () => void }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { value, error, reload } = useLoaded<SecurityView>(
    "security",
    () => 60,
  );
  const [dialog, setDialog] = useState<"enable" | "disable">();
  const [busy, setBusy] = useState("");
  const date = (text: string) =>
    new Date(text).toLocaleString(
      locale === "fa" ? "fa-IR-u-ca-gregory-nu-latn" : "en-US",
      { dateStyle: "medium", timeStyle: "short" },
    );

  async function revoke(body: { id?: string; others?: boolean }) {
    setBusy(body.id || "others");
    try {
      await api("security/sessions/revoke", body);
      await reload();
      toast.success(
        t(body.others ? "sessionsRevokedOthers" : "sessionRevoked"),
      );
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy("");
    }
  }

  const others = value?.sessions.filter((s) => !s.current).length ?? 0;
  return (
    <Card id="sign-in">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound aria-hidden className="size-4" />
          {t("signInTitle")}
        </CardTitle>
        <CardDescription>{t("signInIntro")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {!value ? (
          <Skeleton className="h-40 w-full" />
        ) : (
          <>
            <section
              className="flex flex-col gap-3"
              aria-labelledby="two-factor-title"
            >
              <div
                className="access-summary"
                data-state={value.two_factor ? "valid" : "off"}
              >
                {value.two_factor ? (
                  <ShieldCheck aria-hidden className="size-5 shrink-0" />
                ) : (
                  <ShieldOff aria-hidden className="size-5 shrink-0" />
                )}
                <div className="min-w-0 flex-1">
                  <p id="two-factor-title" className="font-medium">
                    {t(value.two_factor ? "twoFactorOn" : "twoFactorOff")}
                  </p>
                  <p className="text-sm text-muted-foreground">
                    {value.two_factor
                      ? t("twoFactorOnHelp").replace(
                          "{count}",
                          String(value.recovery_remaining),
                        )
                      : t("twoFactorOffHelp")}
                  </p>
                </div>
                {value.two_factor ? (
                  <Button
                    variant="outline"
                    onClick={() => setDialog("disable")}
                  >
                    {t("twoFactorTurnOff")}
                  </Button>
                ) : (
                  <Button onClick={() => setDialog("enable")}>
                    {t("twoFactorTurnOn")}
                  </Button>
                )}
              </div>
              {value.two_factor && value.recovery_remaining <= 3 && (
                <Alert>
                  <AlertDescription>{t("twoFactorFewCodes")}</AlertDescription>
                </Alert>
              )}
            </section>

            <Separator />

            <section
              className="flex flex-col gap-3"
              aria-labelledby="sessions-title"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3
                  id="sessions-title"
                  className="flex items-center gap-2 text-sm font-medium"
                >
                  <MonitorSmartphone aria-hidden className="size-4" />
                  {t("sessionsTitle")}
                </h3>
                {others > 0 && (
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={Boolean(busy)}
                    onClick={() => void revoke({ others: true })}
                  >
                    {busy === "others" && (
                      <Loader2
                        data-icon="inline-start"
                        className="animate-spin"
                      />
                    )}
                    {t("sessionsRevokeOthers")}
                  </Button>
                )}
              </div>
              <ul className="flex flex-col divide-y rounded-lg border">
                {value.sessions.map((s) => {
                  const agent = describeAgent(s.agent);
                  const name =
                    [agent.browser, agent.os].filter(Boolean).join(" · ") ||
                    t("sessionUnknownBrowser");
                  return (
                    <li
                      key={s.id}
                      className="flex flex-wrap items-center gap-3 p-3"
                    >
                      <div className="min-w-0 flex-1">
                        <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
                          <bdi>{name}</bdi>
                          {s.current && (
                            <Badge variant="secondary">
                              {t("sessionThisBrowser")}
                            </Badge>
                          )}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          <bdi dir="ltr">{s.address || "—"}</bdi>
                          {" · "}
                          {t("sessionLastActive").replace(
                            "{date}",
                            date(s.last_seen),
                          )}
                        </p>
                      </div>
                      {!s.current && (
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={Boolean(busy)}
                          aria-label={`${t("sessionRevoke")}: ${name}, ${s.address}`}
                          onClick={() => void revoke({ id: s.id })}
                        >
                          {busy === s.id && (
                            <Loader2
                              data-icon="inline-start"
                              className="animate-spin"
                            />
                          )}
                          {t("sessionRevoke")}
                        </Button>
                      )}
                    </li>
                  );
                })}
              </ul>
              <p className="text-xs text-muted-foreground">
                {t("sessionsHelp")}
              </p>
            </section>

            <Separator />

            <section
              className="flex flex-col gap-3"
              aria-labelledby="password-title"
            >
              <h3 id="password-title" className="text-sm font-medium">
                {t("account")}
              </h3>
              <p className="text-sm text-muted-foreground">
                {t("passwordHelp")}
              </p>
              <CommandBlock text="sudo gtm password" />
            </section>
          </>
        )}
      </CardContent>
      <CardFooter>
        <Button variant="outline" onClick={logout}>
          <LogOut data-icon="inline-start" />
          {t("signOut")}
        </Button>
      </CardFooter>
      <EnableTwoFactor
        open={dialog === "enable"}
        onClose={() => setDialog(undefined)}
        done={() => void reload()}
      />
      <DisableTwoFactor
        open={dialog === "disable"}
        onClose={() => setDialog(undefined)}
        done={() => void reload()}
      />
    </Card>
  );
}

function EnableTwoFactor({
  open,
  onClose,
  done,
}: {
  open: boolean;
  onClose: () => void;
  done: () => void;
}) {
  const t = useT();
  const [setup, setSetup] = useState<TwoFactorSetup>();
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[]>();
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [touched, setTouched] = useState(false);

  function reset() {
    setSetup(undefined);
    setCode("");
    setCodes(undefined);
    setSaved(false);
    setFailure("");
    setTouched(false);
  }

  async function start() {
    setBusy(true);
    setFailure("");
    try {
      setSetup(await api<TwoFactorSetup>("security/two-factor/setup", {}));
    } catch (e) {
      setFailure(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function verify() {
    setTouched(true);
    if (!sixDigits(code)) return;
    setBusy(true);
    setFailure("");
    try {
      const result = await api<{ recovery: string[] }>(
        "security/two-factor/enable",
        {
          code: code.trim(),
        },
      );
      setCodes(result.recovery);
      done();
    } catch (e) {
      setFailure(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  function download() {
    if (!codes) return;
    const text = `${t("twoFactorFileHeader")}\n${window.location.host}\n\n${codes.join("\n")}\n`;
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    link.download = "gtm-recovery-codes.txt";
    link.click();
    URL.revokeObjectURL(link.href);
  }

  useEffect(() => {
    // A fresh secret each time the dialog opens; nothing is saved until the
    // first code is verified.
    if (open && !setup && !codes) void start();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const qr = setup ? qrPath(setup.qr) : undefined;
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        // Recovery codes are shown once; closing needs the saved checkbox.
        if (next || busy || (codes && !saved)) return;
        reset();
        onClose();
      }}
    >
      <DialogContent
        closeLabel={t("close")}
        showCloseButton={!codes || saved}
        className="sm:max-w-lg"
      >
        {codes ? (
          <>
            <DialogHeader>
              <DialogTitle>{t("twoFactorCodesTitle")}</DialogTitle>
              <DialogDescription>{t("twoFactorCodesHelp")}</DialogDescription>
            </DialogHeader>
            <ol
              dir="ltr"
              className="grid grid-cols-2 gap-x-6 gap-y-1 rounded-lg border bg-background p-4 font-mono text-sm"
              aria-label={t("twoFactorCodesTitle")}
            >
              {codes.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ol>
            <div className="flex flex-wrap gap-2">
              <CopyButton
                text={codes.join("\n")}
                label={t("twoFactorCopyCodes")}
              />
              <Button type="button" variant="outline" onClick={download}>
                <Download data-icon="inline-start" />
                {t("twoFactorDownloadCodes")}
              </Button>
            </div>
            <Field orientation="horizontal">
              <Checkbox
                id="two-factor-saved"
                checked={saved}
                onCheckedChange={(next) => setSaved(next === true)}
              />
              <FieldLabel htmlFor="two-factor-saved" className="font-normal">
                {t("twoFactorSaved")}
              </FieldLabel>
            </Field>
            <DialogFooter>
              <Button
                disabled={!saved}
                onClick={() => {
                  reset();
                  onClose();
                }}
              >
                {t("done")}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>{t("twoFactorSetupTitle")}</DialogTitle>
              <DialogDescription>{t("twoFactorSetupHelp")}</DialogDescription>
            </DialogHeader>
            <div className="flex flex-col items-center gap-3 sm:flex-row sm:items-start">
              <div className="two-factor-qr shrink-0">
                {qr ? (
                  <svg
                    viewBox={`0 0 ${qr.size} ${qr.size}`}
                    width="176"
                    height="176"
                    role="img"
                    aria-label={t("twoFactorQR")}
                    shapeRendering="crispEdges"
                  >
                    <rect width={qr.size} height={qr.size} fill="#fff" />
                    <path d={qr.d} fill="#000" />
                  </svg>
                ) : (
                  <Skeleton className="size-44" />
                )}
              </div>
              <div className="flex min-w-0 flex-1 flex-col gap-2 text-sm">
                <p className="text-muted-foreground">{t("twoFactorManual")}</p>
                <p
                  dir="ltr"
                  className="break-all rounded-md border bg-background p-2 font-mono text-xs"
                >
                  {setup ? groupSecret(setup.secret) : "…"}
                </p>
                {setup && (
                  <CopyButton
                    text={setup.secret}
                    label={t("twoFactorCopySecret")}
                    size="sm"
                  />
                )}
              </div>
            </div>
            <form
              id="two-factor-verify"
              noValidate
              onSubmit={(event) => {
                event.preventDefault();
                void verify();
              }}
            >
              <FieldGroup>
                <Field data-invalid={touched && !sixDigits(code)}>
                  <FieldLabel htmlFor="two-factor-code">
                    {t("twoFactorCode")}
                  </FieldLabel>
                  <Input
                    id="two-factor-code"
                    dir="ltr"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    pattern="[0-9]*"
                    className="max-w-40 font-mono tracking-widest"
                    value={code}
                    disabled={!setup || busy}
                    aria-invalid={touched && !sixDigits(code)}
                    onChange={(event) =>
                      setCode(event.target.value.replace(/\D/g, ""))
                    }
                  />
                  {touched && !sixDigits(code) ? (
                    <FieldError>{t("twoFactorCodeInvalid")}</FieldError>
                  ) : (
                    <FieldDescription>
                      {t("twoFactorCodeHelp")}
                    </FieldDescription>
                  )}
                </Field>
              </FieldGroup>
            </form>
            {failure && (
              <Alert variant="destructive" role="alert">
                <AlertDescription>{failure}</AlertDescription>
              </Alert>
            )}
            <DialogFooter>
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => {
                  reset();
                  onClose();
                }}
              >
                {t("cancel")}
              </Button>
              <Button
                type="submit"
                form="two-factor-verify"
                disabled={!setup || busy}
              >
                {busy && (
                  <Loader2 data-icon="inline-start" className="animate-spin" />
                )}
                {t("twoFactorVerify")}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function DisableTwoFactor({
  open,
  onClose,
  done,
}: {
  open: boolean;
  onClose: () => void;
  done: () => void;
}) {
  const t = useT();
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  function close() {
    setPassword("");
    setCode("");
    setFailure("");
    onClose();
  }
  async function submit() {
    if (!password || !code.trim()) {
      setFailure(t("twoFactorDisableMissing"));
      return;
    }
    setBusy(true);
    setFailure("");
    try {
      await api("security/two-factor/disable", { password, code: code.trim() });
      toast.success(t("twoFactorDisabled"));
      done();
      close();
    } catch (e) {
      setFailure(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog open={open} onOpenChange={(next) => !next && !busy && close()}>
      <DialogContent closeLabel={t("close")} className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("twoFactorDisableTitle")}</DialogTitle>
          <DialogDescription>{t("twoFactorDisableHelp")}</DialogDescription>
        </DialogHeader>
        <form
          id="two-factor-disable"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            void submit();
          }}
        >
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="two-factor-password">
                {t("password")}
              </FieldLabel>
              <Input
                id="two-factor-password"
                type="password"
                autoComplete="current-password"
                value={password}
                disabled={busy}
                onChange={(event) => setPassword(event.target.value)}
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="two-factor-disable-code">
                {t("twoFactorCodeOrRecovery")}
              </FieldLabel>
              <Input
                id="two-factor-disable-code"
                dir="ltr"
                autoComplete="one-time-code"
                className="font-mono"
                value={code}
                disabled={busy}
                onChange={(event) => setCode(event.target.value)}
              />
            </Field>
          </FieldGroup>
        </form>
        {failure && (
          <Alert variant="destructive" role="alert">
            <AlertDescription>{failure}</AlertDescription>
          </Alert>
        )}
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={close}>
            {t("cancel")}
          </Button>
          <Button
            type="submit"
            form="two-factor-disable"
            variant="destructive"
            disabled={busy}
          >
            {busy && (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            )}
            {t("twoFactorTurnOff")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
