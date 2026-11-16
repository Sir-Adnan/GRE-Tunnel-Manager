import { useContext, useState } from "react";
import { CheckCircle2, ChevronRight, Circle, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useLoaded } from "@/features/operations/hooks";
import type { AccessView } from "@/features/settings/access";
import { number } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import {
  checklist,
  checklistHidden,
  hideChecklist,
  type ChecklistInput,
} from "./checklist";

/** First-run checklist on the overview. Each step reflects the server's
 * real state; the card disappears once everything is done or it is hidden. */
export function GettingStarted({
  connections,
  add,
  navigate,
}: {
  connections: number;
  add: () => void;
  navigate: (page: string, params?: Record<string, string>) => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [hidden, setHidden] = useState(checklistHidden);
  const [now] = useState(() => Date.now());
  // Nothing is loaded once the card is hidden.
  const path = (p: string) => (hidden ? "" : p);
  const access = useLoaded<AccessView>(path("access"), () => 0).value;
  const security = useLoaded<ChecklistInput["security"]>(
    path("security"),
    () => 0,
  ).value;
  const health = useLoaded<ChecklistInput["health"]>(
    path("health"),
    () => 0,
  ).value;
  const snapshots = useLoaded<ChecklistInput["snapshots"]>(
    path("snapshots"),
    () => 0,
  ).value;
  const notify = useLoaded<ChecklistInput["notify"]>(
    path("notifications"),
    () => 0,
  ).value;
  if (hidden || !access) return null;
  const items = checklist(
    { access, security, connections, health, snapshots, notify },
    now,
  );
  const done = items.filter((item) => item.done).length;
  if (done === items.length) return null;
  const percent = Math.round((done / items.length) * 100);
  return (
    <Card className="getting-started">
      <CardHeader>
        <CardTitle>{t("startTitle")}</CardTitle>
        <CardDescription>
          {t("startProgress")
            .replace("{done}", number(done, locale))
            .replace("{total}", number(items.length, locale))}
        </CardDescription>
        <CardAction>
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label={t("startHide")}
            title={t("startHide")}
            onClick={() => {
              hideChecklist(true);
              setHidden(true);
            }}
          >
            <X />
          </Button>
        </CardAction>
        <div
          className="getting-started-meter"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={items.length}
          aria-valuenow={done}
          aria-label={t("startTitle")}
        >
          <span style={{ inlineSize: `${percent}%` }} />
        </div>
      </CardHeader>
      <CardContent>
        <ol className="getting-started-list">
          {items.map((item) => (
            <li key={item.id} data-done={item.done || undefined}>
              {item.done ? (
                <CheckCircle2
                  aria-hidden
                  className="size-5 shrink-0 text-success-text"
                />
              ) : (
                <Circle
                  aria-hidden
                  className="size-5 shrink-0 text-muted-foreground"
                />
              )}
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">
                  {t(`start_${item.id}`)}
                  {item.done && (
                    <span className="sr-only"> ({t("startDone")})</span>
                  )}
                </p>
                {!item.done && (
                  <p className="text-xs text-muted-foreground">
                    {t(`start_${item.id}Help`)}
                  </p>
                )}
              </div>
              {!item.done && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    item.id === "connection"
                      ? add()
                      : navigate(item.page, item.params)
                  }
                >
                  {t("startSetUp")}
                  <ChevronRight
                    data-icon="inline-end"
                    className="rtl:rotate-180"
                  />
                </Button>
              )}
            </li>
          ))}
        </ol>
      </CardContent>
    </Card>
  );
}
