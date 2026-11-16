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
import { errorMessage, LocaleContext, useT } from "@/lib/i18n";
import { usePoll } from "@/lib/use-poll";
import { api } from "@/lib/api";
import { useLoaded } from "@/features/operations/hooks";
import { certificateSource, certificateState, type AccessView } from "./access";
import { CertificateActions } from "./CertificateActions";

const sourceHelp = {
  http: "tlsHTTPHelp",
  managed: "tlsManagedHelp",
  external: "tlsExternalHelp",
  selfSigned: "tlsSelfSignedHelp",
} as const;

/** TLS status describes the certificate actually loaded by this public process,
 * plus the secret-free renewal record. Keys and ACME accounts stay root-only. */
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
  const source = certificateSource(value);
  const renewal = value?.renewal;
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
      setFailure(errorMessage(e));
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
        {source === "managed" && renewal?.last_error && (
          <Alert>
            <AlertDescription>
              <span className="font-medium">{t("tlsRenewalFailed")}</span>{" "}
              <bdi dir="ltr">{renewal.last_error}</bdi>
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
                  {t(sourceHelp[source])}
                </p>
              </div>
              <Badge variant="outline">
                {renewal?.staging
                  ? t("tlsStaging")
                  : encrypted
                    ? "HTTPS"
                    : "HTTP"}
              </Badge>
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
                  <dt>{t("tlsRenewal")}</dt>
                  <dd>
                    {source === "managed"
                      ? `${t("tlsRenewal_managed")} ${date(renewal?.renew_after)}`
                      : t(`tlsRenewal_${source}`)}
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
          <summary>{t("tlsTrustedGuide")}</summary>
          <div className="flex flex-col gap-3 pt-4">
            <p className="text-sm text-muted-foreground">{t("tlsIssueHelp")}</p>
            <CommandBlock
              text={`sudo gtm https issue --domain ${value?.host || "panel.example.com"}`}
            />
            <p className="text-xs text-muted-foreground">
              {t("tlsIssueDetails")}
            </p>
            <p className="pt-2 text-sm font-medium">{t("tlsRenewalGuide")}</p>
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
          </div>
        </details>
      </CardContent>
      <CardFooter className="flex flex-wrap items-center justify-between gap-3">
        <CertificateActions value={value} reload={reload} />
        <Button
          variant="ghost"
          size="sm"
          title={t("tlsReloadHelp")}
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
