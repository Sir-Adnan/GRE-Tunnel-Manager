// A change saved with "Safe apply" waits for confirmation: this bar counts
// down, keeps it, or reverts it now. The server reverts on its own when the
// time runs out, even with the browser closed.
import { Check, Undo2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useLoaded, useNow } from "@/features/operations/hooks";
import { useT } from "@/lib/i18n";

type Pending = { pending: null | { action: string; summary: string; deadline: string; started: string } };

export function SafeChangeBanner({
  run,
  refreshKey,
}: {
  run: (request: unknown) => Promise<void>;
  /** Changes with the saved configuration, so a new pending change shows at once. */
  refreshKey: string;
}) {
  const t = useT();
  // A new key is a new path, which loads at once (the query is ignored by the server).
  const { value, reload } = useLoaded<Pending>(`changes/pending?v=${refreshKey}`, (v) => (v?.pending ? 5 : 60));
  const now = useNow(Boolean(value?.pending));
  const pending = value?.pending;
  if (!pending) return null;
  const left = Math.max(0, Math.round((new Date(pending.deadline).getTime() - now) / 1000));
  const clock = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
  const act = (action: string) => void run({ action }).finally(() => void reload());
  return (
    <div className="safe-banner" role="status" aria-live="polite">
      <Undo2 className="size-4 shrink-0" aria-hidden />
      <p className="min-w-0 flex-1 text-sm">
        <span className="font-medium">{t("safeBannerTitle").replace("{t}", clock)}</span>{" "}
        <span className="text-muted-foreground">
          {t(`safeAction_${pending.action}`)}
          {pending.summary && (
            <>
              {" · "}
              <bdi dir="ltr">{pending.summary}</bdi>
            </>
          )}
        </span>
      </p>
      <div className="flex shrink-0 gap-2">
        <Button size="sm" variant="outline" onClick={() => act("change-revert")}>
          {t("safeBannerRevert")}
        </Button>
        <Button size="sm" onClick={() => act("change-confirm")}>
          <Check data-icon="inline-start" />
          {t("safeBannerKeep")}
        </Button>
      </div>
    </div>
  );
}
