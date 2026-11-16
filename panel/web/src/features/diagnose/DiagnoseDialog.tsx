import { Loader2, RefreshCw, Stethoscope } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useT } from "@/lib/i18n";
import { DiagnoseResults } from "./DiagnoseResults";
import { useDiagnosis } from "./useDiagnosis";

/** The guided "why is this down" check for one connection or GRE tunnel. */
export function DiagnoseDialog({
  owner,
  name,
  onClose,
}: {
  owner?: string;
  name?: string;
  onClose: () => void;
}) {
  const t = useT();
  const { report, error, busy, run } = useDiagnosis(owner);
  return (
    <Dialog open={Boolean(owner)} onOpenChange={(open) => !open && onClose()}>
      <DialogContent closeLabel={t("close")} className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Stethoscope className="size-4 text-muted-foreground" aria-hidden />
            {t("diagTitle")}
          </DialogTitle>
          <DialogDescription>
            <bdi>{name || owner}</bdi> · {t("diagIntro")}
          </DialogDescription>
        </DialogHeader>
        <DiagnoseResults report={report} error={error} />
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t("close")}
          </Button>
          <Button disabled={busy} onClick={run}>
            {busy ? (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            ) : (
              <RefreshCw data-icon="inline-start" />
            )}
            {t("diagAgain")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
