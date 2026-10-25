import { useState } from "react";
import { RefreshCw, Download, ExternalLink } from "lucide-react";
import { api } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { HelpTip } from "@/components/help";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";

type Release = {
  id: string;
  version: string;
  installed: string;
  peer_version?: string;
  supported: string;
  source: string;
  url: string;
  revision: string;
  update: boolean;
  error?: string;
};
export function EngineUpdates({ run }: { run: (r: unknown) => Promise<void> }) {
  const t = useT(),
    [releases, setReleases] = useState<Release[]>(),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [selected, setSelected] = useState<Release>();
  async function check() {
    setBusy(true);
    setError("");
    try {
      setReleases(await api<Release[]>("engines/releases"));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function update() {
    if (!selected) return;
    setBusy(true);
    setError("");
    try {
      await run({
        action: "engine-update",
        components: [selected.id],
        engine_revision: selected.revision,
      });
      setSelected(undefined);
      setReleases(undefined);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="flex min-w-0 flex-col gap-3 rounded-xl border p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <h2 className="font-medium">{t("engineMaintenance")}</h2>
          <HelpTip>{t("engineMaintenanceHelp")}</HelpTip>
        </div>
        <Button variant="outline" disabled={busy} onClick={check}>
          <RefreshCw data-icon="inline-start" />
          {t(busy ? "working" : "checkEngineUpdates")}
        </Button>
      </div>
      {error && (
        <Alert variant="destructive" role="alert">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {releases && (
        <div className="grid min-w-0 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {releases.map((r) => (
            <div
              key={r.id}
              className="flex min-w-0 flex-col gap-3 rounded-lg border p-3"
            >
              <div className="flex items-center justify-between gap-2">
                <bdi className="font-medium">
                  {r.id === "haproxy"
                    ? "HAProxy"
                    : r.id === "realm"
                      ? "Realm"
                      : r.id}
                </bdi>
                <Badge variant="outline">
                  {t(
                    r.source === "upstream"
                      ? "officialRelease"
                      : "distributionCandidate",
                  )}
                </Badge>
              </div>
              <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-2 text-xs">
                <dt>{t("installed")}</dt>
                <dd className="text-end">
                  <bdi className="break-all font-mono">
                    {r.installed || "—"}
                  </bdi>
                </dd>
                {r.peer_version && (
                  <>
                    <dt>frps</dt>
                    <dd className="text-end">
                      <bdi className="font-mono">{r.peer_version}</bdi>
                    </dd>
                  </>
                )}
                <dt>
                  {t(
                    r.source === "upstream"
                      ? "latestRelease"
                      : "distributionCandidate",
                  )}
                </dt>
                <dd className="text-end">
                  <bdi className="break-all font-mono">{r.version || "—"}</bdi>
                </dd>
                {r.source === "upstream" && (
                  <>
                    <dt>{t("verifiedVersion")}</dt>
                    <dd className="text-end">
                      <bdi className="font-mono">{r.supported}</bdi>
                    </dd>
                  </>
                )}
              </dl>
              {r.error && (
                <p className="text-xs text-destructive">
                  {t("engineCheckFailed")}
                </p>
              )}
              <div className="mt-auto flex flex-wrap items-center justify-between gap-2">
                <a
                  href={r.url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs underline underline-offset-4"
                >
                  {t("officialSource")}
                  <ExternalLink className="size-3" />
                </a>
                {r.update && (
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy}
                    onClick={() => setSelected(r)}
                  >
                    <Download data-icon="inline-start" />
                    {t("updateEngine")}
                  </Button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      <Dialog
        open={!!selected}
        onOpenChange={(v) => !v && !busy && setSelected(undefined)}
      >
        <DialogContent closeLabel={t("close")}>
          <DialogHeader>
            <DialogTitle>
              {t("updateEngine")} · <bdi>{selected?.id}</bdi>
            </DialogTitle>
            <DialogDescription>{t("engineUpdateConfirm")}</DialogDescription>
          </DialogHeader>
          <p className="font-mono" dir="ltr">
            {selected?.installed} → {selected?.supported}
          </p>
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setSelected(undefined)}
            >
              {t("cancel")}
            </Button>
            <Button disabled={busy} onClick={update}>
              {t(busy ? "working" : "updateEngine")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  );
}
