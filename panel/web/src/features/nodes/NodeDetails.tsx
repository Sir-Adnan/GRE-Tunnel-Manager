import { useContext } from "react";
import { endpoint } from "@/lib/api";
import { LocaleContext, useT } from "@/lib/i18n";
import { engineName } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogBody,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import type { Node } from "./types";
import { NodeTraffic } from "./NodeTraffic";

export function NodeDetails({
  node,
  onClose,
}: {
  node: Node;
  onClose: () => void;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent
        closeLabel={t("close")}
        scrollLayout="body"
        className="dialog-shell sm:max-w-2xl"
      >
        <DialogHeader>
          <DialogTitle>{node.name}</DialogTitle>
          <DialogDescription>{t("nodeDetailHelp")}</DialogDescription>
        </DialogHeader>
        <DialogBody>
          <Tabs
            defaultValue="inventory"
            dir={locale === "fa" ? "rtl" : "ltr"}
            className="min-w-0"
          >
            <TabsList>
              <TabsTrigger value="inventory">{t("connections")}</TabsTrigger>
              {!node.local && (
                <TabsTrigger value="traffic">{t("nodeTraffic")}</TabsTrigger>
              )}
            </TabsList>
            <TabsContent value="inventory" className="min-w-0">
              <div className="flex min-w-0 flex-col gap-4">
                <dl className="flex flex-col gap-2 text-sm">
                  <dt>{t("nodeIdentity")}</dt>
                  <dd className="break-all font-mono text-xs">
                    <bdi>{node.id}</bdi>
                  </dd>
                  <dt>{t("os")}</dt>
                  <dd>
                    <bdi>{node.inventory?.host.os || t("notReported")}</bdi>
                  </dd>
                  <dt>{t("capabilities")}</dt>
                  <dd className="break-all">
                    <bdi>
                      {node.capabilities.join(" · ") || t("notReported")}
                    </bdi>
                  </dd>
                </dl>
                {node.inventory?.connections.map((c) => (
                  <div
                    key={c.id}
                    className="flex flex-wrap items-center justify-between gap-2 border-b py-3"
                  >
                    <span className="min-w-0 break-words">{c.name}</span>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant="outline">{engineName(c.engine)}</Badge>
                      <Badge variant="outline">
                        <bdi>{endpoint(c.bind, c.ports)}</bdi>
                      </Badge>
                      <Badge variant="outline">
                        {t(c.status || (c.enabled ? "configured" : "disabled"))}
                      </Badge>
                    </div>
                  </div>
                ))}
                {node.inventory?.resources.map((r) => (
                  <div
                    key={r.id}
                    className="flex flex-wrap justify-between gap-2 border-b py-3"
                  >
                    <bdi className="break-all">{r.name}</bdi>
                    <Badge variant="outline">
                      {engineName(r.engine)} · {t(r.status)}
                    </Badge>
                  </div>
                ))}
              </div>
            </TabsContent>
            {!node.local && (
              <TabsContent value="traffic" className="min-w-0">
                <div className="min-w-0">
                  <NodeTraffic node={node} />
                </div>
              </TabsContent>
            )}
          </Tabs>
        </DialogBody>
      </DialogContent>
    </Dialog>
  );
}
