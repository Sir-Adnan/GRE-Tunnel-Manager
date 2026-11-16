// This server's addresses, uplink first, with the saved settings that use each.
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { fill } from "@/features/firewall/text";
import { useT } from "@/lib/i18n";
import type { AddressReport } from "./model";

export function HostAddresses({ report }: { report: AddressReport }) {
  const t = useT();
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
                  </span>
                </div>
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
