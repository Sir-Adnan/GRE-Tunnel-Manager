import { useContext } from "react";
import { CircleCheck, ShieldCheck, TriangleAlert, Undo2 } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { LocaleContext, useT } from "@/lib/i18n";
import { useNow } from "@/features/operations/hooks";
import { duration, stamp } from "@/features/health/format";
import type { OptimizeWatch } from "./types";

/** The auto-undo watch: a countdown while active, then its outcome. */
export function WatchStatus({ watch }: { watch?: OptimizeWatch }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const now = useNow(watch?.result === "active");
  if (!watch || watch.result === "cancelled") return null;
  const names = (watch.down ?? []).join(locale === "fa" ? "، " : ", ");
  if (watch.result === "active") {
    const left = Math.max(0, (Date.parse(watch.until) - now) / 1000);
    return (
      <Alert className="opt-watch" data-state="active" role="status">
        <ShieldCheck />
        <AlertTitle>{t("optWatchActive")}</AlertTitle>
        <AlertDescription>
          {t("optWatchActiveBody")
            .replace("{n}", String(watch.baseline.length))
            .replace("{left}", duration(left, locale))}
        </AlertDescription>
      </Alert>
    );
  }
  if (watch.result === "kept")
    return (
      <Alert className="opt-watch" data-state="kept">
        <CircleCheck />
        <AlertTitle>{t("optWatchKept")}</AlertTitle>
        <AlertDescription>
          {t("optWatchKeptBody").replace("{t}", stamp(watch.ended, locale))}
        </AlertDescription>
      </Alert>
    );
  return (
    <Alert variant="destructive" className="opt-watch" data-state={watch.result}>
      {watch.result === "undone" ? <Undo2 /> : <TriangleAlert />}
      <AlertTitle>
        {watch.result === "undone" ? t("optWatchUndone") : t("optWatchFailed")}
      </AlertTitle>
      <AlertDescription>
        {(watch.result === "undone" ? t("optWatchUndoneBody") : t("optWatchFailedBody"))
          .replace("{t}", stamp(watch.ended, locale))
          .replace("{names}", names || "—")
          .replace("{e}", watch.error ?? "")}
      </AlertDescription>
    </Alert>
  );
}
