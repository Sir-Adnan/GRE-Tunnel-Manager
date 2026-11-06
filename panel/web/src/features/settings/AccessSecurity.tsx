import { useContext, useState } from "react";
import { LockKeyhole, RefreshCw, ShieldCheck, ShieldAlert } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { CommandBlock } from "@/components/CommandBlock";
import { LocaleContext, useT } from "@/lib/i18n";
import { usePoll } from "@/lib/use-poll";
import { api } from "@/lib/api";
import { useLoaded } from "@/features/operations/hooks";
import { certificateState, type AccessView } from "./access";

/** TLS status describes the certificate actually loaded by this public process.
 * Renewal sources and private keys remain local to the operator's ACME client. */
export function AccessSecurity() {
  const t = useT(),
    locale = useContext(LocaleContext);
  const { value, error, reload } = useLoaded<AccessView>("access", () => 60);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [reloaded, setReloaded] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  usePoll(async () => setNow(Date.now()), { seconds: 60, immediate: false });
  const state = certificateState(value, now);
  const encrypted = value?.protocol === "https";
  const Icon = encrypted ? ShieldCheck : ShieldAlert;
  const date = (text?: string) =>
    text
      ? new Date(text).toLocaleString(
          locale === "fa" ? "fa-IR-u-ca-gregory-nu-latn" : "en-US",
          { dateStyle: "medium", timeStyle: "short" },
        )
      : "—";
  async function renew() {
    setBusy(true);
    setFailure("");
    setReloaded(false);
    try {
      await api("access/reload", {});
      await reload();
      setReloaded(true);
    } catch (e) {
      setFailure(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Card id="access" className="access-security">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <LockKeyhole aria-hidden className="size-4" />
          {t("tlsTitle")}
        </CardTitle>
        <CardDescription>{t("tlsIntro")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        {(error || failure || value?.last_error) && (
          <Alert variant="destructive">
            <AlertDescription>
              {error || failure || value?.last_error}
            </AlertDescription>
          </Alert>
        )}
        {!value ? (
          <Skeleton className="h-28 w-full" />
        ) : (
          <>
            <div className="access-summary" data-state={state}>
              <Icon aria-hidden className="size-5 shrink-0" />
              <div className="min-w-0 flex-1">
                <p className="font-medium">{t(`tlsState_${state}`)}</p>
                <p className="text-sm text-muted-foreground">
                  {t(
                    encrypted
                      ? value.self_signed
                        ? "tlsSelfSignedHelp"
                        : "tlsExternalHelp"
                      : "tlsHTTPHelp",
                  )}
                </p>
              </div>
              <Badge variant="outline">{encrypted ? "HTTPS" : "HTTP"}</Badge>
            </div>
            {encrypted && (
              <dl className="access-facts">
                <div>
                  <dt>{t("tlsHost")}</dt>
                  <dd>
                    <bdi dir="ltr">{value.host}</bdi>
                  </dd>
                </div>
                <div>
                  <dt>{t("tlsExpires")}</dt>
                  <dd>{date(value.not_after)}</dd>
                </div>
                <div>
                  <dt>{t("tlsIssuer")}</dt>
                  <dd>
                    <bdi dir="ltr">{value.issuer}</bdi>
                  </dd>
                </div>
                <div>
                  <dt>{t("tlsLoaded")}</dt>
                  <dd>{date(value.loaded)}</dd>
                </div>
                <div className="sm:col-span-2">
                  <dt>{t("tlsFingerprint")}</dt>
                  <dd className="font-mono text-xs">
                    <bdi dir="ltr">{value.fingerprint}</bdi>
                  </dd>
                </div>
              </dl>
            )}
            {reloaded && (
              <p className="text-sm text-muted-foreground" role="status">
                {t("tlsReloaded")}
              </p>
            )}
          </>
        )}
        <details className="advanced-block">
          <summary>{t("tlsRenewalGuide")}</summary>
          <div className="flex flex-col gap-3 pt-4">
            <p className="text-sm text-muted-foreground">
              {t("tlsRenewalHelp")}
            </p>
            <CommandBlock
              text={
                "sudo gtm-panel certificate install \\\n  --cert /etc/letsencrypt/live/panel.example.com/fullchain.pem \\\n  --key /etc/letsencrypt/live/panel.example.com/privkey.pem \\\n  --host panel.example.com"
              }
            />
            <p className="text-xs text-muted-foreground">
              {t("tlsRenewalHook")}
            </p>
            <p className="text-xs text-muted-foreground">
              {t("tlsHTTPUpgrade")}
            </p>
          </div>
        </details>
      </CardContent>
      <CardFooter className="flex flex-wrap justify-between gap-3">
        <p className="max-w-prose text-xs text-muted-foreground">
          {t("tlsReloadHelp")}
        </p>
        <Button
          variant="outline"
          disabled={!encrypted || busy}
          onClick={() => void renew()}
        >
          <RefreshCw
            data-icon="inline-start"
            className={busy ? "animate-spin" : undefined}
          />
          {t(busy ? "working" : "tlsReload")}
        </Button>
      </CardFooter>
    </Card>
  );
}
