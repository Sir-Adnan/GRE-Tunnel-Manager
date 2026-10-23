import { useContext } from "react";
import { Server, Unplug } from "lucide-react";
import { LocaleContext, useT } from "@/lib/i18n";
import { number } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { ActionButton } from "@/components/help";
import type { Node } from "./types";

export function NodeCard({
  node,
  busy,
  onDetails,
  onRevoke,
}: {
  node: Node;
  busy: boolean;
  onDetails: () => void;
  onRevoke: () => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const date = (value?: string) =>
    value
      ? new Date(value).toLocaleString(
          locale === "fa" ? "fa-IR-u-nu-latn" : "en-US",
        )
      : t("notReported");
  return (
    <Card key={node.id} className="min-w-0">
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <Server className="size-5 shrink-0" />
          <Badge variant={node.status === "online" ? "secondary" : "outline"}>
            {t(`node_${node.status}`)}
          </Badge>
        </div>
        <CardTitle className="break-words">{node.name}</CardTitle>
        <CardDescription>
          {t(node.local ? "localNode" : "remoteNode")}
          {node.version && (
            <>
              {" "}
              · <bdi>v{node.version}</bdi>
            </>
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {node.inventory ? (
          <>
            <p className="break-all text-sm">
              <bdi>
                {node.inventory.host.addresses?.join(" · ") || t("notReported")}
              </bdi>
            </p>
            <div className="flex flex-wrap gap-2">
              <Badge variant="outline">
                {t("connections")} ·{" "}
                {number(node.inventory.connections?.length || 0, locale)}
              </Badge>
              <Badge variant="outline">
                GRE / Reverse ·{" "}
                {number(node.inventory.resources?.length || 0, locale)}
              </Badge>
            </div>
          </>
        ) : (
          <p className="text-sm text-muted-foreground">
            {t(node.local ? "localInventoryError" : "nodeWaitingHelp")}
          </p>
        )}
        <dl className="flex flex-col gap-2 text-xs">
          <div className="flex flex-wrap justify-between gap-2">
            <dt className="text-muted-foreground">{t("lastSeen")}</dt>
            <dd>{date(node.last_seen)}</dd>
          </div>
          <div className="flex flex-wrap justify-between gap-2">
            <dt className="text-muted-foreground">{t("inventoryObserved")}</dt>
            <dd>{date(node.observed)}</dd>
          </div>
        </dl>
        {node.status === "offline" && (
          <p className="text-xs leading-6 text-muted-foreground">
            {t("nodeOfflineHelp")}
          </p>
        )}
        {node.failure && !node.local && node.status === "degraded" && (
          <p className="text-xs leading-6 text-muted-foreground">
            {t("nodeInventoryError")}
          </p>
        )}
      </CardContent>
      <CardFooter className="flex flex-wrap justify-between gap-2">
        <Button size="sm" variant="outline" onClick={onDetails}>
          {t("nodeDetails")}
        </Button>
        {!node.local && node.status !== "revoked" && (
          <ActionButton
            label={t("revokeNode")}
            size="icon-sm"
            variant="ghost"
            disabled={busy}
            onClick={onRevoke}
          >
            <Unplug />
          </ActionButton>
        )}
      </CardFooter>
    </Card>
  );
}
