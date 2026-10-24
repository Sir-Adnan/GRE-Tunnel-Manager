import { useContext } from "react";
import { Code2, Pencil, Activity } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogBody,
  DialogFooter,
} from "@/components/ui/dialog";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { HelpTip } from "@/components/help";
import { Status } from "@/components/shared";
import { CopyButton } from "@/components/CopyButton";
import { LocaleContext, useT } from "@/lib/i18n";
import { engineName } from "@/lib/format";
import { endpoint } from "@/lib/api";
import type { Connection } from "@/lib/api";
import { usePanelRoute } from "@/lib/use-panel-route";

export function ConnectionDetails({
  row,
  onClose,
  onEdit,
  onConfig,
}: {
  row: Connection;
  onClose: () => void;
  onEdit: () => void;
  onConfig: () => void;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const { params, updateParams } = usePanelRoute();
  const tab =
    params.get("detail") === "destinations" ? "destinations" : "summary";
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent
        closeLabel={t("close")}
        scrollLayout="body"
        className="dialog-shell sm:max-w-2xl"
      >
        <DialogHeader>
          <DialogTitle className="break-words">{row.name}</DialogTitle>
          <DialogDescription>
            <bdi>{engineName(row.engine)}</bdi> · <bdi>{row.id}</bdi>
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <Tabs
            dir={locale === "fa" ? "rtl" : "ltr"}
            value={tab}
            onValueChange={(detail) => updateParams({ detail })}
            className="gap-5"
          >
            <TabsList variant="line" aria-label={t("connectionDetails")}>
              <TabsTrigger value="summary">
                {t("connectionOverview")}
              </TabsTrigger>
              <TabsTrigger value="destinations">
                {t("destinations")} ({row.targets.length})
              </TabsTrigger>
            </TabsList>
            <TabsContent value="summary">
              <dl className="detail-grid">
                <div>
                  <dt>{t("status")}</dt>
                  <dd>
                    <Status
                      value={
                        row.status || (row.enabled ? "configured" : "disabled")
                      }
                    />
                  </dd>
                </div>
                <div>
                  <dt>{t("protocol")}</dt>
                  <dd>
                    <bdi>{row.protocol.toUpperCase()}</bdi>
                  </dd>
                </div>
                <div>
                  <dt>{t("listener")}</dt>
                  <dd>
                    <bdi dir="ltr" className="break-all font-mono text-xs">
                      {endpoint(row.bind, row.ports)}
                    </bdi>
                  </dd>
                </div>
                <div>
                  <dt>{t("strategy")}</dt>
                  <dd>{t(row.strategy)}</dd>
                </div>
              </dl>
              <p className="mt-5 text-xs leading-6 text-muted-foreground">
                {t("connectionStateHelp")}
              </p>
            </TabsContent>
            <TabsContent value="destinations">
              <div className="mb-3 flex items-center gap-1 text-sm">
                <span>{t(row.strategy)}</span>
                <HelpTip>{t("weightHelp")}</HelpTip>
              </div>
              <ul className="divide-y divide-border">
                {row.targets.map((target, i) => (
                  <li
                    key={i}
                    className="flex flex-wrap items-center justify-between gap-2 py-3"
                  >
                    <CopyButton
                      variant="ghost"
                      className="h-auto max-w-full min-w-0 whitespace-normal text-start [overflow-wrap:anywhere]"
                      dir="ltr"
                      text={endpoint(target.ip, target.port)}
                      label={endpoint(target.ip, target.port)}
                    />
                    <span className="text-xs text-muted-foreground">
                      {t("weight")}: <bdi>{target.weight}</bdi>
                    </span>
                  </li>
                ))}
              </ul>
            </TabsContent>
          </Tabs>
        </DialogBody>
        <DialogFooter className="flex-row flex-wrap">
          <Button
            variant="ghost"
            onClick={() => {
              window.location.hash = `/traffic?tab=details&resource=${encodeURIComponent(row.id)}`;
            }}
          >
            <Activity data-icon="inline-start" />
            {t("traffic")}
          </Button>
          <Button variant="outline" onClick={onConfig}>
            <Code2 data-icon="inline-start" />
            {t("viewConfig")}
          </Button>
          <Button onClick={onEdit}>
            <Pencil data-icon="inline-start" />
            {t("edit")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
