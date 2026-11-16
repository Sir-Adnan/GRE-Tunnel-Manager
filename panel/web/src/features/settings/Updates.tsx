import { useContext, useEffect, useState } from "react";
import { toast } from "sonner";
import {
  ArrowUpCircle,
  CheckCircle2,
  ExternalLink,
  Loader2,
  RefreshCw,
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
import { Skeleton } from "@/components/ui/skeleton";
import { CommandBlock } from "@/components/CommandBlock";
import { Confirm, type ConfirmRequest } from "@/features/maintenance/Confirm";
import { useLoaded } from "@/features/operations/hooks";
import { ApiError, api, operate } from "@/lib/api";
import { errorMessage, LocaleContext, useT } from "@/lib/i18n";
import {
  pendingUpdate,
  releaseNotes,
  rememberUpdate,
  updateOutcome,
  type PendingUpdate,
  type UpdateView,
} from "./update";

function useDate() {
  const locale = useContext(LocaleContext);
  return (text?: string) =>
    text
      ? new Date(text).toLocaleString(
          locale === "fa" ? "fa-IR-u-ca-gregory-nu-latn" : "en-US",
          { dateStyle: "medium", timeStyle: "short" },
        )
      : "—";
}

/** Settings › Updates: the daily check, release notes and a one-click
 * update. The update runs in its own systemd unit, so the restart it causes
 * cannot interrupt it; this page waits, then reloads into the new release. */
export function Updates() {
  const t = useT();
  const date = useDate();
  const { value, error, reload } = useLoaded<UpdateView>("update", (v) =>
    v?.running ? 5 : 600,
  );
  const [pending, setPending] = useState<PendingUpdate | undefined>(
    pendingUpdate,
  );
  const [checking, setChecking] = useState(false);
  const [failure, setFailure] = useState("");
  const [confirm, setConfirm] = useState<ConfirmRequest>();

  // While an update runs the panel restarts: errors are expected. A 401
  // means the new panel is up (sessions do not survive a restart).
  useEffect(() => {
    if (!pending) return;
    let stopped = false;
    const timer = window.setInterval(async () => {
      try {
        const view = await api<UpdateView>("update");
        if (stopped) return;
        const outcome = updateOutcome(pending, view, Date.now());
        if (outcome === "succeeded") window.location.reload();
        if (outcome === "failed") {
          rememberUpdate(undefined);
          setPending(undefined);
          setFailure(view.run?.error || t("updateFailed"));
          void reload();
        }
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) window.location.reload();
        else if (updateOutcome(pending, undefined, Date.now()) === "failed") {
          rememberUpdate(undefined);
          setPending(undefined);
          setFailure(t("updateFailed"));
        }
      }
    }, 3000);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [pending, reload, t]);

  async function check() {
    setChecking(true);
    setFailure("");
    try {
      await operate({ action: "panel-update-check" });
      await reload();
    } catch (e) {
      setFailure(errorMessage(e));
      void reload();
    } finally {
      setChecking(false);
    }
  }

  function start() {
    if (!value?.check.latest) return;
    const latest = value.check.latest;
    setConfirm({
      title: t("updateConfirmTitle").replace("{version}", latest),
      body: t("updateConfirmBody"),
      action: t("updateNow"),
      run: async () => {
        setFailure("");
        try {
          await operate({ action: "panel-update-install" });
          const next = { from: value.current, to: latest, started: Date.now() };
          rememberUpdate(next);
          setPending(next);
        } catch (e) {
          setFailure(errorMessage(e));
          throw e;
        }
      },
    });
  }

  const latest = value?.check.latest;
  const run = value?.run;
  const updating = Boolean(pending) || Boolean(value?.running);
  return (
    <Card id="updates">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ArrowUpCircle aria-hidden className="size-4" />
          {t("updatesTitle")}
        </CardTitle>
        <CardDescription>{t("updatesIntro")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        {(error || failure) && (
          <Alert variant="destructive" role="alert">
            <AlertDescription>
              <span className="font-medium">{t("updateFailedTitle")}</span>{" "}
              <bdi dir="ltr">{failure || error}</bdi>
            </AlertDescription>
          </Alert>
        )}
        {!failure && run?.state === "failed" && !updating && (
          <Alert>
            <AlertDescription>
              {t("updateLastFailed").replace(
                "{date}",
                date(run.finished || run.started),
              )}{" "}
              <bdi dir="ltr">{run.error}</bdi>
            </AlertDescription>
          </Alert>
        )}
        {!value ? (
          <Skeleton className="h-24 w-full" />
        ) : updating ? (
          <div className="access-summary" data-state="expiring" role="status">
            <Loader2 aria-hidden className="size-5 shrink-0 animate-spin" />
            <div className="min-w-0 flex-1">
              <p className="font-medium">
                {t("updateRunning").replace(
                  "{version}",
                  pending?.to || run?.to || latest || "",
                )}
              </p>
              <p className="text-sm text-muted-foreground">
                {t("updateRunningHelp")}
              </p>
            </div>
          </div>
        ) : (
          <div
            className="access-summary"
            data-state={value.available ? "available" : "valid"}
          >
            {value.available ? (
              <ArrowUpCircle aria-hidden className="size-5 shrink-0" />
            ) : (
              <CheckCircle2 aria-hidden className="size-5 shrink-0" />
            )}
            <div className="min-w-0 flex-1">
              <p className="font-medium">
                {value.available
                  ? t("updateAvailable").replace("{version}", latest || "")
                  : t(latest ? "updateLatest" : "updateNotChecked")}
              </p>
              <p className="text-sm text-muted-foreground">
                {t(
                  value.available ? "updateAvailableHelp" : "updateLatestHelp",
                )}
              </p>
            </div>
            <Badge variant="outline">
              <bdi dir="ltr">v{value.current}</bdi>
            </Badge>
          </div>
        )}
        {value && (
          <dl className="access-facts">
            <div>
              <dt>{t("updateInstalled")}</dt>
              <dd>
                <bdi dir="ltr">v{value.current}</bdi>
              </dd>
            </div>
            <div>
              <dt>{t("updateLatestRelease")}</dt>
              <dd>
                {latest ? (
                  <a
                    className="inline-flex items-center gap-1 underline-offset-4 hover:underline"
                    href={releaseNotes(latest)}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <bdi dir="ltr">v{latest}</bdi>
                    <ExternalLink aria-hidden className="size-3" />
                    <span className="sr-only">{t("updateReleaseNotes")}</span>
                  </a>
                ) : (
                  "—"
                )}
              </dd>
            </div>
            <div>
              <dt>{t("updateChecked")}</dt>
              <dd>
                {value.check.checked && !value.check.checked.startsWith("0001")
                  ? date(value.check.checked)
                  : "—"}
              </dd>
            </div>
            {value.check.error && (
              <div>
                <dt>{t("updateCheckError")}</dt>
                <dd>
                  <bdi dir="ltr">{value.check.error}</bdi>
                </dd>
              </div>
            )}
          </dl>
        )}
        <details className="advanced-block">
          <summary>{t("updateTerminal")}</summary>
          <div className="flex flex-col gap-3 pt-4">
            <p className="text-sm text-muted-foreground">
              {t("updateTerminalHelp")}
            </p>
            <CommandBlock text="sudo gtm update" />
          </div>
        </details>
      </CardContent>
      <CardFooter className="flex flex-wrap gap-2">
        {value?.available && (
          <Button disabled={updating} onClick={start}>
            <ArrowUpCircle data-icon="inline-start" />
            {t("updateTo").replace("{version}", latest || "")}
          </Button>
        )}
        <Button
          variant="outline"
          disabled={checking || updating || !value}
          onClick={() => void check()}
        >
          <RefreshCw
            data-icon="inline-start"
            className={checking ? "animate-spin" : undefined}
          />
          {t(checking ? "working" : "updateCheckNow")}
        </Button>
      </CardFooter>
      <Confirm request={confirm} onClose={() => setConfirm(undefined)} />
    </Card>
  );
}

/** After the reload that follows an update, say how it ended once. */
export function UpdateResultNotice({ version }: { version?: string }) {
  const t = useT();
  useEffect(() => {
    const pending = pendingUpdate();
    if (!pending || !version) return;
    if (version !== pending.from) {
      rememberUpdate(undefined);
      toast.success(t("updateDone").replace("{version}", version));
      return;
    }
    let cancelled = false;
    api<UpdateView>("update")
      .then((view) => {
        if (cancelled) return;
        const outcome = updateOutcome(pending, view, Date.now());
        if (outcome === "running") return;
        rememberUpdate(undefined);
        if (outcome === "succeeded")
          toast.success(t("updateDone").replace("{version}", view.current));
        else toast.error(view.run?.error || t("updateFailed"));
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [version, t]);
  return null;
}
