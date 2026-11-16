// Firewall page: findings first, then the host firewall, per-connection
// ports and access, and abuse protection. Edits collect in a draft; Apply
// sends them with an optional automatic revert that the server runs itself.
import { useEffect, useMemo, useState } from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { HelpTip } from "@/components/help";
import { PageTitle } from "@/components/shared";
import { Segmented } from "@/components/Segmented";
import { useLoaded } from "@/features/operations/hooks";
import type { Inventory } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { usePanelRoute } from "@/lib/use-panel-route";
import { AccessSheet } from "./AccessSheet";
import { ConnectionRules } from "./ConnectionRules";
import { Findings } from "./Findings";
import {
  accessOf,
  findings,
  sameSettings,
  withAccess,
  withUFW,
  type FirewallSettings,
  type FirewallStatus,
} from "./model";
import { PendingBanner } from "./parts";
import { fill } from "./text";
import { Protection } from "./Protection";
import { StatusTiles } from "./StatusTiles";

const windows = ["0", "60", "120", "300"];

export function Firewall({
  inventory,
  run,
}: {
  inventory: Inventory;
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const {
    value: status,
    error,
    reload,
  } = useLoaded<FirewallStatus>("firewall", (v) => (v?.pending ? 5 : 30));
  // A badge on a connection card links here with ?connection=ID.
  const focus = usePanelRoute().params.get("connection") ?? "";
  const loaded = Boolean(status);
  useEffect(() => {
    if (!focus || !loaded) return;
    const reduce = window.matchMedia(
      "(prefers-reduced-motion: reduce)",
    ).matches;
    document.getElementById(`fw-${focus}`)?.scrollIntoView({
      block: "center",
      behavior: reduce ? "auto" : "smooth",
    });
  }, [focus, loaded]);
  const [draft, setDraft] = useState<FirewallSettings>();
  const [editing, setEditing] = useState<string>();
  const [seconds, setSeconds] = useState("60");
  const [busy, setBusy] = useState(false);
  // Discarding remounts the sections that keep their own text fields.
  const [generation, setGeneration] = useState(0);
  const connections = inventory.connections;
  const settings = draft ?? status?.settings;
  const dirty = Boolean(
    draft && status && !sameSettings(draft, status.settings),
  );
  const items = useMemo(
    () => (status ? findings(status, connections) : []),
    [status, connections],
  );

  async function act(request: unknown, keepDraft = true) {
    setBusy(true);
    try {
      await run(request);
      if (!keepDraft) setDraft(undefined);
    } catch {
      // The operation dialog shows the error; the draft stays for a retry.
    } finally {
      setBusy(false);
      await reload();
    }
  }
  const change = (next: FirewallSettings) => setDraft(next);
  const apply = () =>
    status &&
    draft &&
    void act(
      {
        action: "firewall-apply",
        firewall: {
          revision: status.revision,
          settings: draft,
          seconds: Number(seconds),
        },
      },
      false,
    );
  const editingConnection = connections.find((c) => c.id === editing);

  return (
    <div className="page-stack fw-page" data-dirty={dirty}>
      <PageTitle title={t("firewall")} description={t("fwIntro")} />
      {status?.pending && (
        <PendingBanner
          deadline={status.pending}
          busy={busy}
          keep={() => void act({ action: "firewall-confirm" })}
          revert={() => void act({ action: "firewall-revert" }, false)}
        />
      )}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>
            {t("fwLoadFailed")} {error}
          </AlertDescription>
        </Alert>
      )}
      {!status || !settings ? (
        !error && (
          <div className="flex flex-col gap-4" aria-busy>
            <Skeleton className="h-14 w-full" />
            <div className="fw-tiles">
              {[0, 1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-36" />
              ))}
            </div>
            <Skeleton className="h-64 w-full" />
          </div>
        )
      ) : (
        <>
          <Findings
            items={items}
            busy={busy}
            repair={() => void act({ action: "firewall-repair" })}
            openUFW={(id) => {
              change(withUFW(settings, id, true));
              document
                .getElementById(`fw-${id}`)
                ?.scrollIntoView({ block: "center" });
            }}
          />
          <StatusTiles status={status} />
          <ConnectionRules
            connections={connections}
            status={status}
            settings={settings}
            busy={busy}
            edit={setEditing}
            focus={focus}
            setUFW={(id, open) => change(withUFW(settings, id, open))}
          />
          <Protection
            key={`${status.revision}-${generation}`}
            status={status}
            settings={settings}
            busy={busy}
            change={change}
          />
        </>
      )}
      {dirty && status && (
        <div className="fw-savebar" role="region" aria-label={t("fwUnsaved")}>
          <p className="fw-savebar-title">{t("fwUnsaved")}</p>
          <div className="fw-savebar-window">
            <span className="flex items-center gap-1 text-xs text-muted-foreground">
              {t("fwSafeWindow")}
              <HelpTip label={`${t("fwSafeWindow")} · ?`}>
                {t("fwSafeHelp")}
              </HelpTip>
            </span>
            <Segmented
              label={t("fwSafeWindow")}
              value={seconds}
              onChange={setSeconds}
              options={windows.map((w) => ({
                value: w,
                label:
                  w === "0"
                    ? t("fwSafeOff")
                    : Number(w) < 120
                      ? fill(t("fwSafeSeconds"), { n: w })
                      : fill(t("fwSafeMinutes"), { n: Number(w) / 60 }),
              }))}
            />
          </div>
          <div className="fw-savebar-actions">
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => {
                setDraft(undefined);
                setGeneration((g) => g + 1);
              }}
            >
              {t("fwDiscard")}
            </Button>
            <Button disabled={busy} onClick={apply}>
              {t("fwApply")}
            </Button>
          </div>
        </div>
      )}
      <AccessSheet
        connection={editingConnection}
        initial={editing && settings ? accessOf(settings, editing) : undefined}
        close={() => setEditing(undefined)}
        save={(access) => {
          if (settings) change(withAccess(settings, access));
          setEditing(undefined);
        }}
      />
    </div>
  );
}
