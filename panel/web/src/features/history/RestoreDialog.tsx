import { useContext, useEffect, useState } from "react";
import { Loader2, RotateCcw, TriangleAlert } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import { LocaleContext, useT } from "@/lib/i18n";
import { stamp } from "@/features/health/format";
import { ChangeLine } from "./ChangeLine";
import type { HistoryEntry, HistoryReview } from "./types";

/** Shows what restoring a point changes now, then restores it. */
export function RestoreDialog({
  entry,
  onClose,
  restore,
}: {
  entry?: HistoryEntry;
  onClose: () => void;
  restore: (point: string, revision: string) => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [review, setReview] = useState<HistoryReview>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const point = entry?.point;
  useEffect(() => {
    if (!point) return;
    const controller = new AbortController();
    api<HistoryReview>(
      `history/review?point=${encodeURIComponent(point)}`,
      undefined,
      controller.signal,
    )
      .then(setReview)
      .catch((e) => {
        if (!controller.signal.aborted)
          setError(e instanceof Error ? e.message : String(e));
      });
    return () => controller.abort();
  }, [point]);
  const nothing = review && review.changes.length === 0;
  return (
    <Dialog open={Boolean(entry)} onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent closeLabel={t("close")} className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("histRestoreTitle")}</DialogTitle>
          <DialogDescription>
            {t("histRestoreBody").replace(
              "{t}",
              entry ? stamp(entry.time, locale) : "",
            )}
          </DialogDescription>
        </DialogHeader>
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {!review && !error ? (
          <Skeleton className="h-24 w-full" />
        ) : review && nothing ? (
          <p className="text-sm text-muted-foreground">{t("histNothing")}</p>
        ) : review ? (
          <div className="flex flex-col gap-2">
            <span className="text-xs font-medium text-muted-foreground">
              {t("histRestoreChanges")}
            </span>
            <ul className="hist-changes max-h-72 overflow-y-auto">
              {review.changes.map((c) => (
                <ChangeLine key={c.id + c.kind} change={c} />
              ))}
            </ul>
          </div>
        ) : null}
        {review && !nothing && (
          <Alert>
            <TriangleAlert />
            <AlertDescription>{t("histRestoreWarn")}</AlertDescription>
          </Alert>
        )}
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={onClose}>
            {t("cancel")}
          </Button>
          <Button
            disabled={busy || !review || nothing}
            onClick={() => {
              if (!review) return;
              setBusy(true);
              restore(review.point, review.revision)
                .then(onClose)
                .catch(() => undefined)
                .finally(() => setBusy(false));
            }}
          >
            {busy ? (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            ) : (
              <RotateCcw data-icon="inline-start" />
            )}
            {t("histRestoreConfirm")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
