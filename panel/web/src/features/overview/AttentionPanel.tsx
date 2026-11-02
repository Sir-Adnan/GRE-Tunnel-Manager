import { CircleCheck, CircleAlert, ChevronRight } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useT } from "@/lib/i18n";
import type { AttentionItem } from "@/lib/attention";

/** What an operator should look at first; an empty list is a positive, explicit state. */
export function AttentionPanel({
  items,
  navigate,
}: {
  items: AttentionItem[];
  navigate: (page: string, params?: Record<string, string>) => void;
}) {
  const t = useT();
  const open = (item: AttentionItem) =>
    item.kind === "connection"
      ? navigate("connections", { connection: item.id })
      : item.kind === "engine"
        ? navigate("components")
        : navigate(item.id.startsWith("gre") ? "gre" : "reverse");
  return (
    <Card className="attention-card" data-state={items.length ? "alert" : "ok"}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {items.length ? (
            <CircleAlert className="size-4 text-warning-text" />
          ) : (
            <CircleCheck className="size-4 text-success-text" />
          )}
          {t("needsAttention")}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <div className="flex flex-col gap-1">
            <p className="font-medium">{t("allHealthy")}</p>
            <p className="text-sm leading-6 text-muted-foreground">
              {t("allHealthyHelp")}
            </p>
          </div>
        ) : (
          <ul className="flex flex-col gap-1">
            {items.slice(0, 6).map((item) => (
              <li key={`${item.kind}-${item.id}`}>
                <button
                  type="button"
                  className="attention-row"
                  onClick={() => open(item)}
                >
                  <span className="status-dot is-alert" aria-hidden />
                  <span className="min-w-0 flex-1 text-start">
                    <span className="block truncate font-medium">
                      <bdi>{item.name}</bdi>
                    </span>
                    <span className="block text-xs text-muted-foreground">
                      {item.kind === "engine"
                        ? t("engineMissing")
                        : t(item.detail)}
                    </span>
                  </span>
                  <ChevronRight className="size-4 shrink-0 text-muted-foreground rtl:rotate-180" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
