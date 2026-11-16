// IP addresses page: this server's addresses and what uses each, a warning
// when a saved setting still uses an address the server lost, the one-screen
// "IP changed" fix and the additional addresses the manager keeps.
import { CircleAlert, Plus, Replace } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { PageTitle } from "@/components/shared";
import { useLoaded } from "@/features/operations/hooks";
import { fill } from "@/features/firewall/text";
import { useT } from "@/lib/i18n";
import { usePanelRoute } from "@/lib/use-panel-route";
import { ExtraAddresses } from "./ExtraAddresses";
import { ExtraSheet } from "./ExtraSheet";
import { HostAddresses } from "./HostAddresses";
import { IPChangeSheet } from "./IPChangeSheet";
import { usesOf, type AddressReport } from "./model";

export function Addresses({ refresh }: { refresh: () => Promise<void> }) {
  const t = useT();
  const {
    value: report,
    error,
    reload,
  } = useLoaded<AddressReport>("addresses", () => 30);
  // ?fix=ADDRESS (from the Overview), ?change=1 and ?extra=1 (command palette) open a sheet.
  const { params, updateParams } = usePanelRoute();
  const fix = params.get("fix") ?? "";
  const changing = Boolean(fix) || params.has("change");
  const adding = params.has("extra");
  const close = () => updateParams({ fix: "", change: "", extra: "" });
  const reloadAll = async () => {
    await reload();
    await refresh().catch(() => undefined);
  };
  const stale = report?.stale ?? [];

  return (
    <div className="page-stack ip-page">
      <PageTitle
        title={t("addresses")}
        description={t("ipIntro")}
        action={
          <div className="ip-actions">
            <Button
              variant="outline"
              disabled={!report}
              onClick={() => updateParams({ extra: "1" }, true)}
            >
              <Plus data-icon="inline-start" />
              {t("ipExtraAdd")}
            </Button>
            <Button
              disabled={!report}
              onClick={() => updateParams({ change: "1" }, true)}
            >
              <Replace data-icon="inline-start" />
              {t("ipChangeTitle")}
            </Button>
          </div>
        }
      />
      {error && (
        <Alert variant="destructive">
          <AlertDescription>
            {t("ipLoadFailed")} {error}
          </AlertDescription>
        </Alert>
      )}
      {!report ? (
        !error && (
          <div className="flex flex-col gap-4" aria-busy>
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-56 w-full" />
            <Skeleton className="h-40 w-full" />
          </div>
        )
      ) : (
        <>
          {stale.map((address) => (
            <div key={address} className="ip-stale" role="alert">
              <CircleAlert className="size-5 shrink-0" aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="font-medium">
                  {t("ipStaleTitle").split("{a}")[0]}
                  <bdi dir="ltr" className="font-mono">
                    {address}
                  </bdi>
                  {t("ipStaleTitle").split("{a}")[1]}
                </p>
                <p className="text-sm text-muted-foreground">
                  {fill(t("ipStaleHelp"), {
                    n: usesOf(report, "local", address).length,
                  })}
                </p>
              </div>
              <Button onClick={() => updateParams({ fix: address }, true)}>
                {t("ipFixNow")}
              </Button>
            </div>
          ))}
          <HostAddresses report={report} />
          <ExtraAddresses
            report={report}
            add={() => updateParams({ extra: "1" }, true)}
            changed={reloadAll}
          />
        </>
      )}
      {report && (
        <IPChangeSheet
          open={changing}
          report={report}
          initialOld={fix}
          close={close}
          changed={reloadAll}
        />
      )}
      {report && (
        <ExtraSheet
          open={adding}
          report={report}
          close={close}
          changed={reloadAll}
        />
      )}
    </div>
  );
}
