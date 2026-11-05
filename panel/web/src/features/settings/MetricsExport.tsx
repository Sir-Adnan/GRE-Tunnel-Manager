import { useState } from "react";
import { Activity, KeyRound, Loader2 } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Field, FieldContent, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Switch } from "@/components/ui/switch";
import { CommandBlock } from "@/components/CommandBlock";
import { operate } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { useLoaded } from "@/features/operations/hooks";

type PrometheusView = {
  enabled: boolean;
  token_set: boolean;
  revision: number;
  token?: string;
  path: string;
};

/** Read-only Prometheus endpoint: off by default, bearer token, shown once. */
export function MetricsExport() {
  const t = useT();
  const { value, error, reload } = useLoaded<PrometheusView>("prometheus", () => 0);
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  async function configure(enabled: boolean, rotate = false) {
    if (!value) return;
    setBusy(true);
    setFailure("");
    try {
      const job = await operate({
        action: "prometheus-configure",
        prometheus: { enabled, rotate, revision: value.revision },
      });
      const next = job.result as PrometheusView;
      setToken(next.token ?? "");
      await reload();
    } catch (e) {
      setFailure(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  const origin = window.location.origin;
  const scrape = `scrape_configs:
  - job_name: tunnel-manager
    scheme: ${window.location.protocol.replace(":", "")}
    metrics_path: /metrics
    authorization:
      credentials: ${token || "<token>"}
    static_configs:
      - targets: ["${window.location.host}"]`;
  return (
    <Card id="metrics">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="size-4 text-muted-foreground" aria-hidden />
          {t("promTitle")}
        </CardTitle>
        <CardDescription>{t("promIntro")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        {(error || failure) && (
          <Alert variant="destructive">
            <AlertDescription>{error || failure}</AlertDescription>
          </Alert>
        )}
        <Field orientation="horizontal" className="rounded-lg border p-4">
          <FieldContent>
            <FieldLabel htmlFor="prom-enabled">{t("promEnable")}</FieldLabel>
            <FieldDescription>{t("promEnableHelp")}</FieldDescription>
          </FieldContent>
          {busy ? (
            <Loader2 className="size-4 animate-spin" aria-label={t("promBusy")} />
          ) : (
            <Switch
              id="prom-enabled"
              checked={Boolean(value?.enabled)}
              disabled={!value}
              onCheckedChange={(on) => void configure(on)}
            />
          )}
        </Field>
        {token && (
          <Alert>
            <KeyRound />
            <AlertTitle>{t("promTokenOnce")}</AlertTitle>
            <AlertDescription className="flex min-w-0 flex-col gap-3">
              <code dir="ltr" className="break-all text-xs">{token}</code>
            </AlertDescription>
          </Alert>
        )}
        {value?.enabled && (
          <>
            <p className="text-sm text-muted-foreground">
              {t("promEndpoint")}{" "}
              <code dir="ltr" className="text-xs">{`${origin}${value.path}`}</code>
            </p>
            <CommandBlock text={scrape} />
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="max-w-prose text-xs text-muted-foreground">
                {window.location.protocol === "http:" ? t("promHttpWarn") : t("promRotateHelp")}
              </p>
              <Button variant="outline" size="sm" disabled={busy} onClick={() => void configure(true, true)}>
                <KeyRound data-icon="inline-start" />
                {t("promRotate")}
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
