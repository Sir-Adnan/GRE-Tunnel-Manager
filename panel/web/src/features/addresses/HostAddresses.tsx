// This server's addresses, uplink first, with the saved settings that use each.
// An address added by hand (nothing re-creates it at boot) is marked
// temporary and can be kept in an owned unit with one click.
import { useState } from "react";
import { Pin, TriangleAlert } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { fill } from "@/features/firewall/text";
import { operate } from "@/lib/api";
import { errorMessage, useT } from "@/lib/i18n";
import type { AddressReport, HostAddress } from "./model";

export function HostAddresses({
  report,
  changed,
}: {
  report: AddressReport;
  changed: () => Promise<void>;
}) {
  const t = useT();
  const [keeping, setKeeping] = useState("");
  async function keep(a: HostAddress) {
    setKeeping(a.address);
    try {
      await operate({
        action: "address-extra-keep",
        address: {
          address: `${a.address}/${a.prefix}`,
          interface: a.interface,
        },
      });
      toast.success(fill(t("ipKept"), { ip: a.address }));
      await changed();
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setKeeping("");
    }
  }
  const extra = new Set(report.extra.map((x) => x.address.split("/")[0]));
  const rows = report.addresses.filter((a) => !a.container);
  const containers = report.addresses.length - rows.length;
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("ipServerAddresses")}</CardTitle>
        <CardDescription>{t("ipServerAddressesHelp")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        {rows.length === 0 && (
          <p className="text-sm text-muted-foreground">{t("ipNoAddresses")}</p>
        )}
        <ul className="ip-list">
          {rows.map((a) => {
            const uses = report.uses.filter(
              (u) => u.use === "local" && u.address === a.address,
            );
            return (
              <li key={`${a.interface}-${a.address}`} className="ip-row">
                <div className="ip-row-main">
                  <bdi dir="ltr" className="ip-address">
                    {a.address}
                    <span className="text-muted-foreground">/{a.prefix}</span>
                  </bdi>
                  <span className="fw-chips">
                    <span className="fw-chip">
                      <bdi dir="ltr">{a.interface}</bdi>
                    </span>
                    {a.uplink && (
                      <span className="fw-pill" data-tone="ok">
                        <span className="fw-pill-dot" aria-hidden />
                        {t("ipUplink")}
                      </span>
                    )}
                    {extra.has(a.address) && (
                      <span className="fw-pill">
                        <span className="fw-pill-dot" aria-hidden />
                        {t("ipExtraBadge")}
                      </span>
                    )}
                    {a.temporary && (
                      <span className="fw-pill" data-tone="warn">
                        <span className="fw-pill-dot" aria-hidden />
                        {t("ipTemporary")}
                      </span>
                    )}
                  </span>
                </div>
                {a.temporary && (
                  <div className="ip-temporary">
                    <p>
                      <TriangleAlert aria-hidden />
                      {t("ipTemporaryHelp")}
                    </p>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={keeping !== ""}
                      onClick={() => void keep(a)}
                    >
                      <Pin data-icon="inline-start" />
                      {keeping === a.address ? t("working") : t("ipKeep")}
                    </Button>
                  </div>
                )}
                <p className="ip-row-uses">
                  {uses.length === 0
                    ? t("ipUnused")
                    : fill(t("ipUsedBy"), {
                        n: uses.length,
                      })}
                  {uses.length > 0 && (
                    <span className="fw-chips mt-1">
                      {uses.slice(0, 4).map((u) => (
                        <span key={`${u.kind}-${u.id}`} className="fw-chip">
                          <bdi>{u.name}</bdi>
                        </span>
                      ))}
                      {uses.length > 4 && (
                        <span className="fw-chip">+{uses.length - 4}</span>
                      )}
                    </span>
                  )}
                </p>
              </li>
            );
          })}
        </ul>
        {containers > 0 && (
          <p className="text-xs text-muted-foreground">
            {fill(t("ipContainersHidden"), { n: containers })}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
