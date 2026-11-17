// Additional addresses kept by gtm-addr-N units: state, return route and removal.
import { useState } from "react";
import { Plus, Route, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ActionButton } from "@/components/help";
import { fill } from "@/features/firewall/text";
import { operate } from "@/lib/api";
import { errorMessage, useT } from "@/lib/i18n";
import type { AddressReport, ExtraAddress } from "./model";

export function ExtraAddresses({
  report,
  add,
  changed,
}: {
  report: AddressReport;
  add: () => void;
  changed: () => Promise<void>;
}) {
  const t = useT();
  const [removing, setRemoving] = useState<ExtraAddress>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function remove(x: ExtraAddress) {
    setBusy(true);
    setError("");
    try {
      await operate({ action: "address-extra-delete", address: { id: x.id } });
      toast.success(t("completed"));
      setRemoving(undefined);
      await changed();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }
  const tone = (x: ExtraAddress) => (x.active && x.present ? "ok" : "problem");
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("ipExtraTitle")}</CardTitle>
        <CardDescription>{t("ipExtraHelp")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {report.extra.length === 0 ? (
          <div className="ip-empty">
            <p className="text-sm text-muted-foreground">{t("ipExtraNone")}</p>
            <Button variant="outline" onClick={add}>
              <Plus data-icon="inline-start" />
              {t("ipExtraAdd")}
            </Button>
          </div>
        ) : (
          <ul className="ip-list">
            {report.extra.map((x) => (
              <li key={x.id} className="ip-row">
                <div className="ip-row-head">
                  <bdi dir="ltr" className="ip-address">
                    {x.address}
                  </bdi>
                  <ActionButton
                    variant="ghost"
                    size="icon-sm"
                    className="text-muted-foreground"
                    label={fill(t("ipExtraRemove"), { a: x.address })}
                    onClick={() => setRemoving(x)}
                  >
                    <Trash2 />
                  </ActionButton>
                </div>
                <div className="ip-row-main">
                  <span className="fw-chips">
                    <span className="fw-chip">
                      <bdi dir="ltr">{x.interface}</bdi>
                    </span>
                    <span className="fw-pill" data-tone={tone(x)}>
                      <span className="fw-pill-dot" aria-hidden />
                      {t(
                        !x.active
                          ? "ipExtraStopped"
                          : x.present
                            ? "ipExtraActive"
                            : "ipExtraMissing",
                      )}
                    </span>
                  </span>
                </div>
                <p className="ip-row-uses">
                  <Route aria-hidden />
                  <span>
                    {x.gateway ? (
                      <>
                        {t("ipExtraOwnRoute")}{" "}
                        <bdi dir="ltr" className="font-mono">
                          {x.gateway}
                        </bdi>
                      </>
                    ) : (
                      t("ipExtraMainRoute")
                    )}
                  </span>
                </p>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
      <Dialog
        open={Boolean(removing)}
        onOpenChange={(open) => !open && !busy && setRemoving(undefined)}
      >
        <DialogContent closeLabel={t("close")} className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              {fill(t("ipExtraRemove"), { a: removing?.address ?? "" })}
            </DialogTitle>
            <DialogDescription>{t("ipExtraRemoveHelp")}</DialogDescription>
          </DialogHeader>
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setRemoving(undefined)}
            >
              {t("cancel")}
            </Button>
            <Button
              variant="destructive"
              disabled={busy}
              onClick={() => removing && void remove(removing)}
            >
              {t("ipExtraRemoveConfirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
