import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  BadgeCheck,
  ExternalLink,
  Loader2,
  RotateCw,
  ShieldOff,
} from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
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
import { ApiError, api, operate } from "@/lib/api";
import { errorMessage, useT } from "@/lib/i18n";
import {
  certificateHostError,
  certificateSource,
  certificateState,
  emailValid,
  httpsAddress,
  type AccessView,
} from "./access";

type Phase =
  | { kind: "closed" }
  | { kind: "issue" }
  | { kind: "selfSigned" }
  | { kind: "switching"; url: string };

/** An HTTP panel restarts on HTTPS before the job can answer, so a lost
 * connection after the request means the switch happened. A job that ran and
 * failed reports its reason and leaves the panel unchanged. */
async function restartedOnHTTPS(error: unknown) {
  if (!(error instanceof ApiError) && !(error instanceof TypeError))
    return false;
  await new Promise((resolve) => setTimeout(resolve, 1500));
  try {
    await api("session");
    return false;
  } catch {
    return true;
  }
}

/** Certificate actions run through allowlisted broker jobs: Let's Encrypt
 * over port 80, renewal and a fresh self-signed certificate. Cloudflare DNS
 * stays a terminal command so its token never passes through this process. */
export function CertificateActions({
  value,
  reload,
}: {
  value?: AccessView;
  reload: () => Promise<unknown>;
}) {
  const t = useT();
  const [phase, setPhase] = useState<Phase>({ kind: "closed" });
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [host, setHost] = useState("");
  const [email, setEmail] = useState("");
  const [staging, setStaging] = useState(false);
  const [touched, setTouched] = useState(false);
  const [now] = useState(() => Date.now());
  const http = value?.protocol === "http";
  const source = certificateSource(value);
  const trusted =
    source === "managed" && certificateState(value, now) === "valid";
  const hostError = certificateHostError(host);
  const emailError = emailValid(email) ? "" : "tlsEmailInvalid";
  const target = httpsAddress(host || value?.host || "", window.location);

  function open(kind: "issue" | "selfSigned") {
    setFailure("");
    setTouched(false);
    if (kind === "issue") {
      setHost(value?.host || "");
      setStaging(false);
    }
    setPhase({ kind });
  }

  async function run(request: object, done: string) {
    setBusy(true);
    setFailure("");
    try {
      await operate(request);
      if (http) {
        setPhase({ kind: "switching", url: target });
        return;
      }
      await reload().catch(() => undefined);
      toast.success(t(done));
      setPhase({ kind: "closed" });
    } catch (error) {
      if (http && (await restartedOnHTTPS(error))) {
        setPhase({ kind: "switching", url: target });
        return;
      }
      setFailure(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function renew() {
    setBusy(true);
    try {
      await operate({ action: "certificate-renew" });
      await reload().catch(() => undefined);
      toast.success(t("tlsRenewed"));
    } catch (error) {
      toast.error(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  const close = (next: boolean) =>
    !next &&
    !busy &&
    phase.kind !== "switching" &&
    setPhase({ kind: "closed" });

  return (
    <>
      <div className="flex flex-wrap gap-2">
        <Button
          variant={trusted ? "outline" : "default"}
          disabled={!value || busy}
          onClick={() => open("issue")}
        >
          <BadgeCheck data-icon="inline-start" />
          {t(trusted ? "tlsNewCertificate" : "tlsGetTrusted")}
        </Button>
        {source === "managed" && (
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => void renew()}
          >
            <RotateCw
              data-icon="inline-start"
              className={
                busy && phase.kind === "closed" ? "animate-spin" : undefined
              }
            />
            {t("tlsRenewNow")}
          </Button>
        )}
        {value && source !== "selfSigned" && (
          <Button
            variant="ghost"
            disabled={busy}
            onClick={() => open("selfSigned")}
          >
            <ShieldOff data-icon="inline-start" />
            {t("tlsUseSelfSigned")}
          </Button>
        )}
      </div>

      <Dialog open={phase.kind === "issue"} onOpenChange={close}>
        <DialogContent closeLabel={t("close")} className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t("tlsIssueTitle")}</DialogTitle>
            <DialogDescription>{t("tlsIssueIntro")}</DialogDescription>
          </DialogHeader>
          <form
            id="certificate-issue"
            noValidate
            onSubmit={(event) => {
              event.preventDefault();
              setTouched(true);
              if (hostError || emailError || busy) return;
              void run(
                {
                  action: "certificate-issue",
                  certificate: {
                    host: host.trim(),
                    email: email.trim(),
                    staging,
                  },
                },
                "tlsIssued",
              );
            }}
          >
            <FieldGroup>
              <Field data-invalid={touched && Boolean(hostError)}>
                <FieldLabel htmlFor="certificate-host">
                  {t("tlsIssueHost")}
                </FieldLabel>
                <Input
                  id="certificate-host"
                  dir="ltr"
                  inputMode="url"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="panel.example.com"
                  value={host}
                  disabled={busy}
                  aria-invalid={touched && Boolean(hostError)}
                  onChange={(event) => setHost(event.target.value)}
                />
                {touched && hostError ? (
                  <FieldError>{t(hostError)}</FieldError>
                ) : (
                  <FieldDescription>{t("tlsIssueHostHelp")}</FieldDescription>
                )}
              </Field>
              <Field data-invalid={touched && Boolean(emailError)}>
                <FieldLabel htmlFor="certificate-email">
                  {t("tlsIssueEmail")}
                </FieldLabel>
                <Input
                  id="certificate-email"
                  dir="ltr"
                  type="email"
                  autoComplete="email"
                  value={email}
                  disabled={busy}
                  aria-invalid={touched && Boolean(emailError)}
                  onChange={(event) => setEmail(event.target.value)}
                />
                {touched && emailError ? (
                  <FieldError>{t(emailError)}</FieldError>
                ) : (
                  <FieldDescription>{t("tlsIssueEmailHelp")}</FieldDescription>
                )}
              </Field>
              <Field orientation="horizontal">
                <Checkbox
                  id="certificate-staging"
                  checked={staging}
                  disabled={busy}
                  onCheckedChange={(next) => setStaging(next === true)}
                />
                <FieldLabel
                  htmlFor="certificate-staging"
                  className="font-normal"
                >
                  {t("tlsIssueStaging")}
                </FieldLabel>
              </Field>
            </FieldGroup>
          </form>
          <Alert>
            <AlertDescription>
              {t("tlsIssuePort80")}
              {http && (
                <>
                  {" "}
                  {t("tlsIssueSwitch")}{" "}
                  <bdi dir="ltr" className="font-mono text-xs">
                    {target}
                  </bdi>
                </>
              )}
            </AlertDescription>
          </Alert>
          {failure && (
            <Alert variant="destructive" role="alert">
              <AlertDescription>
                <bdi dir="ltr">{failure}</bdi>
              </AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setPhase({ kind: "closed" })}
            >
              {t("cancel")}
            </Button>
            <Button type="submit" form="certificate-issue" disabled={busy}>
              {busy && (
                <Loader2 data-icon="inline-start" className="animate-spin" />
              )}
              {t(busy ? "tlsIssueWorking" : "tlsIssueAction")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={phase.kind === "selfSigned"} onOpenChange={close}>
        <DialogContent closeLabel={t("close")} className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t("tlsSelfSignedTitle")}</DialogTitle>
            <DialogDescription>{t("tlsSelfSignedBody")}</DialogDescription>
          </DialogHeader>
          {failure && (
            <Alert variant="destructive" role="alert">
              <AlertDescription>
                <bdi dir="ltr">{failure}</bdi>
              </AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setPhase({ kind: "closed" })}
            >
              {t("cancel")}
            </Button>
            <Button
              variant="destructive"
              disabled={busy}
              onClick={() =>
                void run(
                  { action: "certificate-self-signed" },
                  "tlsSelfSignedDone",
                )
              }
            >
              {busy && (
                <Loader2 data-icon="inline-start" className="animate-spin" />
              )}
              {t("tlsUseSelfSigned")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {phase.kind === "switching" && <Switching url={phase.url} />}
    </>
  );
}

/** Counts down, then opens the panel's new HTTPS address. Sessions do not
 * carry over: the restarted panel asks for the password again. */
function Switching({ url }: { url: string }) {
  const t = useT();
  const [seconds, setSeconds] = useState(8);
  useEffect(() => {
    if (seconds <= 0) {
      window.location.assign(url);
      return;
    }
    const timer = window.setTimeout(() => setSeconds(seconds - 1), 1000);
    return () => window.clearTimeout(timer);
  }, [seconds, url]);
  return (
    <Dialog open>
      <DialogContent showCloseButton={false} className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("tlsSwitchingTitle")}</DialogTitle>
          <DialogDescription role="status">
            {t("tlsSwitchingBody").replace(
              "{seconds}",
              String(Math.max(seconds, 0)),
            )}
          </DialogDescription>
        </DialogHeader>
        <p className="font-mono text-sm" dir="ltr">
          {url}
        </p>
        <DialogFooter>
          <Button asChild>
            <a href={url}>
              <ExternalLink data-icon="inline-start" />
              {t("tlsSwitchingOpen")}
            </a>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
