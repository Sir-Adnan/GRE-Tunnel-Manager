// A connection's Check tab: the live packet path and the guided checks.
// Saving a connection opens it here, so every change is verified at once.
import { CircleCheck, Loader2, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { HelpTip } from "@/components/help";
import { useT } from "@/lib/i18n";
import type { Connection } from "@/lib/api";
import { DiagnoseResults } from "@/features/diagnose/DiagnoseResults";
import { useDiagnosis } from "@/features/diagnose/useDiagnosis";
import { PacketPath } from "./PacketPath";

export function ConnectionCheck({
  connection,
  hostname,
  saved,
  run,
}: {
  connection: Connection;
  hostname: string;
  /** Opened right after saving: confirm it first. */
  saved?: boolean;
  run?: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const diagnosis = useDiagnosis(connection.id);
  return (
    <div className="flex min-w-0 flex-col gap-6">
      {saved && (
        <p className="check-saved" role="status">
          <CircleCheck aria-hidden />
          {t("chkSaved")}
        </p>
      )}
      <PacketPath connection={connection} hostname={hostname} run={run} />
      <section
        className="flex min-w-0 flex-col gap-3"
        aria-labelledby={`checks-${connection.id}`}
      >
        <div className="flex items-center gap-2">
          <h3 id={`checks-${connection.id}`} className="path-title">
            {t("chkChecks")}
          </h3>
          <HelpTip label={`${t("chkChecks")} · ?`}>
            {t("chkChecksHelp")}
          </HelpTip>
          <Button
            size="sm"
            variant="ghost"
            className="ms-auto"
            disabled={diagnosis.busy}
            onClick={diagnosis.run}
          >
            {diagnosis.busy ? (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            ) : (
              <RefreshCw data-icon="inline-start" />
            )}
            {t("diagAgain")}
          </Button>
        </div>
        <DiagnoseResults report={diagnosis.report} error={diagnosis.error} />
      </section>
    </div>
  );
}
