// An operation's error as what happened, what to do and (where a page fixes
// it) a button; the engine's own words stay under "Technical details".
import { CircleAlert, RotateCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useT } from "@/lib/i18n";
import { usePanelRoute } from "@/lib/use-panel-route";
import { cleanError, errorKeys } from "@/lib/error-help";

export function ErrorExplain({
  error,
  showTitle = true,
  onNavigate,
}: {
  error: string;
  /** False when the surrounding dialog already shows the title. */
  showTitle?: boolean;
  /** Called before a fix button leaves for another page (close the dialog). */
  onNavigate?: () => void;
}) {
  const t = useT();
  const { navigate } = usePanelRoute();
  const { title, fix, help } = errorKeys(error);
  const lines = cleanError(error);
  const page = help?.page;
  return (
    <div className="error-help" role="alert">
      {showTitle && (
        <p className="error-help-title">
          <CircleAlert aria-hidden />
          {t(title)}
        </p>
      )}
      <div className="flex flex-col gap-0.5">
        <span className="text-xs font-medium text-muted-foreground">
          {t("ehWhat")}
        </span>
        <p className="text-sm leading-relaxed">{t(fix)}</p>
      </div>
      {(page || help?.reload) && (
        <div className="flex flex-wrap gap-2">
          {page && (
            <Button
              size="sm"
              onClick={() => {
                onNavigate?.();
                navigate(page, help?.params);
              }}
            >
              {t(`ehOpen_${page}`)}
            </Button>
          )}
          {help?.reload && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => window.location.reload()}
            >
              <RotateCw data-icon="inline-start" />
              {t("ehReload")}
            </Button>
          )}
        </div>
      )}
      {lines.length > 0 && (
        <details className="error-help-details" open={!help || undefined}>
          <summary>{t("ehDetails")}</summary>
          <pre dir="ltr">{lines.join("\n")}</pre>
        </details>
      )}
    </div>
  );
}
