// The paired address-change job: both servers check, then move their tunnel
// ends; the operator confirms once the tunnel works, or rolls both back.
// Unconfirmed jobs return to the old address by themselves.
import { useCallback, useEffect, useState } from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import type { Node } from "@/features/nodes/types";
import { api } from "@/lib/api";
import { errorMessage, useT } from "@/lib/i18n";
import { usePoll } from "@/lib/use-poll";

type Job = {
  id: string;
  revision: string;
  state: string;
  steps: {
    node: string;
    stage: string;
    result?: { state: string; code?: string };
  }[];
};
const done = (state = "") =>
  ["succeeded", "rolled_back", "needs_attention"].includes(state);

export function ReaddressJob({
  id,
  nodes,
  finished,
}: {
  id: string;
  nodes: Node[];
  finished: () => Promise<void>;
}) {
  const t = useT();
  const [job, setJob] = useState<Job>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    const all = await api<Job[]>("nodes/pairs");
    setJob(all.find((j) => j.id === id));
  }, [id]);
  // Runs at once, then every 2 s until the job has finished.
  usePoll(() => load().catch((e) => setError(errorMessage(e))), {
    seconds: 2,
    enabled: !done(job?.state),
  });
  const state = job?.state ?? "preparing";
  useEffect(() => {
    if (done(state)) void finished();
  }, [state, finished]);
  async function decide(decision: "confirm" | "rollback") {
    if (!job) return;
    setBusy(true);
    setError("");
    try {
      await api("nodes/pairs/decision", {
        id: job.id,
        revision: job.revision,
        decision,
      });
      await load();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }
  const name = (node: string) =>
    node === "local"
      ? t("ipThisServer")
      : nodes.find((n) => n.id === node)?.name || node;
  const tone =
    state === "succeeded"
      ? "ok"
      : ["rolled_back", "needs_attention"].includes(state)
        ? "problem"
        : "warn";
  return (
    <section
      className="ip-job"
      aria-live="polite"
      aria-labelledby={`job-${id}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span id={`job-${id}`} className="text-sm font-medium">
          {t("ipJobTitle")}
        </span>
        <span className="fw-pill" data-tone={tone}>
          <span className="fw-pill-dot" aria-hidden />
          {t(`readdress_${state}`)}
        </span>
      </div>
      <ul className="flex flex-col gap-1.5">
        {job?.steps.map((s, i) => (
          <li
            key={s.node}
            className="flex min-w-0 flex-wrap items-baseline justify-between gap-x-3 text-sm"
          >
            <span className="min-w-0">
              <span className="text-muted-foreground">
                {t(i === 0 ? "readdressChanged" : "readdressPeer")} ·{" "}
              </span>
              <bdi>{name(s.node)}</bdi>
            </span>
            <span className="text-xs text-muted-foreground">
              {t(`pair_${s.result?.state || s.stage}`)}
              {s.result?.code ? ` · ${t(`pairCode_${s.result.code}`)}` : ""}
            </span>
          </li>
        ))}
      </ul>
      {state === "awaiting_confirmation" && (
        <p className="text-xs leading-5">{t("ipJobConfirmHelp")}</p>
      )}
      {error && (
        <Alert variant="destructive">
          <AlertDescription className="[overflow-wrap:anywhere]">
            {error}
          </AlertDescription>
        </Alert>
      )}
      {job && (!done(state) || state === "needs_attention") && (
        <div className="flex flex-wrap gap-2">
          {state === "awaiting_confirmation" && (
            <Button
              size="sm"
              disabled={busy}
              onClick={() => void decide("confirm")}
            >
              {t("ipJobConfirm")}
            </Button>
          )}
          <Button
            size="sm"
            variant="outline"
            disabled={busy || state === "rolling_back"}
            onClick={() => void decide("rollback")}
          >
            {t(
              state === "needs_attention"
                ? "pairRetryRecovery"
                : "ipJobRollback",
            )}
          </Button>
        </div>
      )}
    </section>
  );
}
