// "IP changed" on one screen: whose address changed, old → new, a checklist
// of everything that uses the old one and a single Apply. GRE tunnels whose
// other end is an online Node move on both servers in one confirmable job;
// for any other server the sheet shows the command to run there.
import { useEffect, useMemo, useState } from "react";
import {
  ArrowLeftRight,
  ArrowRight,
  CircleCheck,
  CircleX,
  Layers3,
  Network,
} from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import {
  NativeSelect,
  NativeSelectOption,
} from "@/components/ui/native-select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { CommandBlock } from "@/components/CommandBlock";
import { Segmented } from "@/components/Segmented";
import { useIsMobile } from "@/hooks/use-mobile";
import { fill } from "@/features/firewall/text";
import type { Listing } from "@/features/nodes/types";
import { api, operate } from "@/lib/api";
import { errorMessage, useT } from "@/lib/i18n";
import {
  family,
  manualPeers,
  newChoices,
  oldChoices,
  parseResults,
  partnerNode,
  peerCommand,
  readdressVersion,
  usableAddress,
  usesOf,
  type AddressReport,
  type AddressUse,
  type Use,
} from "./model";
import { ReaddressJob } from "./ReaddressJob";

const kindIcon = { gre: Network, connection: Layers3, reverse: ArrowLeftRight };

function requestID() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

/** What Apply did, kept apart from the report, which no longer lists the moved uses once reloaded. */
type Outcome = {
  uses: AddressUse[];
  peers: string[];
  results: Record<string, "done" | "failed">;
  error: string;
  job?: string;
  jobError: string;
};

function Form({
  report,
  initialOld,
  close,
  changed,
}: {
  report: AddressReport;
  initialOld: string;
  close: () => void;
  changed: () => Promise<void>;
}) {
  const t = useT();
  const [use, setUse] = useState<Use>(
    initialOld || report.stale.length || !oldChoices(report, "remote").length
      ? "local"
      : "remote",
  );
  const choices = oldChoices(report, use);
  const [old, setOld] = useState(
    initialOld && choices.includes(initialOld)
      ? initialOld
      : (choices[0] ?? ""),
  );
  const targets = newChoices(report, old);
  const [next, setNext] = useState(
    use === "local"
      ? targets.includes(report.suggested)
        ? report.suggested
        : (targets[0] ?? "")
      : "",
  );
  const [nodes, setNodes] = useState<Listing["nodes"]>([]);
  useEffect(() => {
    const controller = new AbortController();
    api<Listing>("nodes", undefined, controller.signal)
      .then((v) => setNodes(v.nodes))
      .catch(() => setNodes([]));
    return () => controller.abort();
  }, []);

  const uses = usesOf(report, use, old);
  const gre = uses.filter((u) => u.kind === "gre");
  const remotes = useMemo(() => {
    const out: Record<string, string> = {};
    for (const u of report.uses)
      if (u.kind === "gre" && u.use === "remote") out[u.id] = u.address;
    return out;
  }, [report.uses]);
  const partner = partnerNode(nodes, gre, use, old);
  const auto = Boolean(partner && !partner.blocked);
  const [skipped, setSkipped] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<Outcome>();

  const handledByJob = (u: AddressUse) => auto && u.kind === "gre";
  const items = uses
    .filter((u) => u.editable && !handledByJob(u) && !skipped.has(u.id))
    .map((u) => u.id);
  const problem = !old
    ? "ipNoOld"
    : !usableAddress(next)
      ? "ipBadNew"
      : family(next) !== family(old)
        ? "ipFamilyMismatch"
        : next === old
          ? "ipSameAddress"
          : use === "local" && !targets.includes(next)
            ? "ipNotOnServer"
            : !items.length && !auto
              ? "ipNothingChosen"
              : "";
  const peers =
    use === "local"
      ? manualPeers(gre, remotes, partner)
      : !auto && gre.length
        ? ["other"]
        : [];

  function switchUse(value: Use) {
    setUse(value);
    const list = oldChoices(report, value);
    const first = list[0] ?? "";
    setOld(first);
    const local = newChoices(report, first);
    setNext(
      value === "local"
        ? local.includes(report.suggested)
          ? report.suggested
          : (local[0] ?? "")
        : "",
    );
    setSkipped(new Set());
  }
  function switchOld(value: string) {
    setOld(value);
    if (use === "local") {
      const local = newChoices(report, value);
      setNext(local.includes(next) ? next : (local[0] ?? ""));
    }
    setSkipped(new Set());
  }

  async function apply() {
    if (problem) return;
    setBusy(true);
    const result: Outcome = {
      uses,
      peers,
      results: {},
      error: "",
      jobError: "",
    };
    if (items.length) {
      try {
        const job = await operate({
          action: "address-replace",
          address: { old, new: next, use, items },
        });
        result.results = parseResults(String(job.result ?? ""));
      } catch (e) {
        const text = errorMessage(e);
        result.results = parseResults(text);
        result.error = text;
      }
    }
    if (auto && partner) {
      const self = { id: "local", revision: "" };
      const other = { id: partner.node.id, revision: partner.node.revision };
      try {
        const job = await api<{ id: string }>("nodes/readdress", {
          id: requestID(),
          changed: use === "local" ? self : other,
          peer: use === "local" ? other : self,
          old,
          new: next,
        });
        result.job = job.id;
      } catch (e) {
        result.jobError = errorMessage(e);
      }
    }
    setOutcome(result);
    setBusy(false);
    await changed();
  }

  const head = (
    <SheetHeader>
      <SheetTitle>{t("ipChangeTitle")}</SheetTitle>
      <SheetDescription>{t("ipChangeIntro")}</SheetDescription>
    </SheetHeader>
  );

  if (outcome)
    return (
      <div className="flex min-h-0 flex-1 flex-col">
        {head}
        <div className="fw-sheet-body">
          <p className="ip-move" dir="ltr">
            <bdi className="font-mono">{old}</bdi>
            <ArrowRight className="size-4 shrink-0" aria-hidden />
            <bdi className="font-mono">{next}</bdi>
          </p>
          {Object.keys(outcome.results).length > 0 && (
            <ul className="ip-checks">
              {outcome.uses
                .filter((u) => outcome.results[u.id])
                .map((u) => (
                  <li
                    key={`${u.kind}-${u.id}`}
                    data-ok={outcome.results[u.id] === "done"}
                  >
                    {outcome.results[u.id] === "done" ? (
                      <CircleCheck className="size-4 shrink-0" aria-hidden />
                    ) : (
                      <CircleX className="size-4 shrink-0" aria-hidden />
                    )}
                    <bdi className="min-w-0 flex-1 truncate">{u.name}</bdi>
                    <span className="text-xs">
                      {t(
                        outcome.results[u.id] === "done"
                          ? "ipItemDone"
                          : "ipItemFailed",
                      )}
                    </span>
                  </li>
                ))}
            </ul>
          )}
          {outcome.error && (
            <Alert variant="destructive">
              <AlertDescription className="[overflow-wrap:anywhere]">
                {Object.keys(outcome.results).length
                  ? t("ipSomeFailed")
                  : outcome.error}
              </AlertDescription>
            </Alert>
          )}
          {outcome.job && partner && (
            <ReaddressJob id={outcome.job} nodes={nodes} finished={changed} />
          )}
          {outcome.jobError && (
            <Alert variant="destructive">
              <AlertDescription className="[overflow-wrap:anywhere]">
                {t("ipJobFailed")} {outcome.jobError}
              </AlertDescription>
            </Alert>
          )}
          <PeerCommands peers={outcome.peers} old={old} next={next} use={use} />
        </div>
        <SheetFooter className="fw-sheet-footer flex-row justify-end border-t">
          <Button onClick={close}>{t("fwDone")}</Button>
        </SheetFooter>
      </div>
    );

  return (
    <form
      className="flex min-h-0 flex-1 flex-col"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        void apply();
      }}
    >
      {head}
      <div className="fw-sheet-body">
        <div className="fw-field">
          <span className="text-sm font-medium">{t("ipWhoseAddress")}</span>
          <Segmented
            label={t("ipWhoseAddress")}
            value={use}
            onChange={(v) => switchUse(v as Use)}
            options={[
              { value: "local", label: t("ipThisServer") },
              { value: "remote", label: t("ipOtherServer") },
            ]}
          />
        </div>
        {choices.length === 0 ? (
          <p className="ip-empty text-sm text-muted-foreground">
            {t(use === "local" ? "ipNoLocalUses" : "ipNoRemoteUses")}
          </p>
        ) : (
          <>
            <div className="ip-pair">
              <div className="fw-field min-w-0">
                <label htmlFor="ip-old" className="text-sm font-medium">
                  {t("ipOld")}
                </label>
                <NativeSelect
                  id="ip-old"
                  className="w-full"
                  value={old}
                  onChange={(e) => switchOld(e.target.value)}
                >
                  {choices.map((a) => (
                    <NativeSelectOption key={a} value={a}>
                      {a}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
                {use === "local" && report.stale.includes(old) && (
                  <span className="ip-caption" data-tone="problem">
                    {t("ipGone")}
                  </span>
                )}
              </div>
              <ArrowRight className="ip-pair-arrow" aria-hidden />
              <div className="fw-field min-w-0">
                <label htmlFor="ip-new" className="text-sm font-medium">
                  {t("ipNew")}
                </label>
                {use === "local" ? (
                  <NativeSelect
                    id="ip-new"
                    className="w-full"
                    value={next}
                    disabled={!targets.length}
                    onChange={(e) => setNext(e.target.value)}
                  >
                    {targets.map((a) => (
                      <NativeSelectOption key={a} value={a}>
                        {a}
                      </NativeSelectOption>
                    ))}
                  </NativeSelect>
                ) : (
                  <Input
                    id="ip-new"
                    dir="ltr"
                    inputMode="decimal"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder={
                      family(old) === 6 ? "2001:db8::20" : "198.51.100.20"
                    }
                    value={next}
                    aria-invalid={
                      Boolean(next) &&
                      Boolean(problem) &&
                      problem !== "ipNothingChosen"
                    }
                    onChange={(e) => setNext(e.target.value.trim())}
                  />
                )}
                {use === "local" && next && next === report.suggested && (
                  <span className="ip-caption" data-tone="ok">
                    {t("ipSuggested")}
                  </span>
                )}
              </div>
            </div>
            {use === "local" && !targets.length && (
              <p className="fw-note">{t("ipAddFirst")}</p>
            )}
            {next &&
              problem &&
              !["ipNothingChosen", "ipNotOnServer"].includes(problem) && (
                <p className="text-xs text-destructive" role="alert">
                  {t(problem)}
                </p>
              )}

            <section className="fw-field" aria-labelledby="ip-items-title">
              <div className="flex items-baseline justify-between gap-2">
                <span id="ip-items-title" className="text-sm font-medium">
                  {t("ipWhatChanges")}
                </span>
                <span className="text-xs text-muted-foreground">
                  {fill(t("ipCount"), { n: uses.length })}
                </span>
              </div>
              <ul className="ip-items">
                {uses.map((u) => {
                  const Icon = kindIcon[u.kind];
                  const byJob = handledByJob(u);
                  const id = `ip-item-${u.kind}-${u.id}`;
                  return (
                    <li
                      key={`${u.kind}-${u.id}`}
                      className="ip-item"
                      data-disabled={!u.editable || undefined}
                    >
                      <Checkbox
                        id={id}
                        checked={u.editable && (byJob || !skipped.has(u.id))}
                        disabled={!u.editable || byJob}
                        onCheckedChange={(on) =>
                          setSkipped((s) => {
                            const copy = new Set(s);
                            if (on) copy.delete(u.id);
                            else copy.add(u.id);
                            return copy;
                          })
                        }
                      />
                      <Icon
                        className="size-4 shrink-0 text-muted-foreground"
                        aria-hidden
                      />
                      <label htmlFor={id} className="min-w-0 flex-1">
                        <bdi className="block truncate text-sm font-medium">
                          {u.name}
                        </bdi>
                        <span className="block text-xs text-muted-foreground">
                          {t(`ipUse_${u.kind}_${u.use}`)}
                          {u.kind === "gre" &&
                            use === "local" &&
                            remotes[u.id] && (
                              <>
                                {" · "}
                                <bdi dir="ltr" className="font-mono">
                                  {remotes[u.id]}
                                </bdi>
                              </>
                            )}
                        </span>
                      </label>
                      {byJob && partner ? (
                        <span className="fw-pill" data-tone="ok">
                          <span className="fw-pill-dot" aria-hidden />
                          {t("ipAutoBoth")}
                        </span>
                      ) : !u.editable ? (
                        <span className="fw-pill" data-tone="warn">
                          <span className="fw-pill-dot" aria-hidden />
                          {t("ipRebuild")}
                        </span>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
              {uses.some((u) => !u.editable) && (
                <p className="fw-note">{t("ipRebuildHelp")}</p>
              )}
            </section>

            {partner && (
              <Alert>
                <AlertDescription>
                  {partner.blocked
                    ? fill(
                        t(
                          partner.blocked === "agentOutdated"
                            ? "ipPartnerOutdated"
                            : "ipPartnerOffline",
                        ),
                        {
                          n: partner.node.name,
                          v: readdressVersion,
                        },
                      )
                    : fill(t("ipPartnerAuto"), { n: partner.node.name })}
                </AlertDescription>
              </Alert>
            )}
            <PeerCommands peers={peers} old={old} next={next} use={use} />
          </>
        )}
      </div>
      <SheetFooter className="fw-sheet-footer flex-row justify-end border-t">
        <Button type="button" variant="outline" disabled={busy} onClick={close}>
          {t("cancel")}
        </Button>
        <Button type="submit" disabled={busy || Boolean(problem)}>
          {busy
            ? t("working")
            : fill(t("ipApply"), { n: items.length + (auto ? 1 : 0) })}
        </Button>
      </SheetFooter>
    </form>
  );
}

/** What to run on servers that no Node moves; the other side keeps the old address until then. */
function PeerCommands({
  peers,
  old,
  next,
  use,
}: {
  peers: string[];
  old: string;
  next: string;
  use: Use;
}) {
  const t = useT();
  if (!peers.length) return null;
  const other = use === "local" ? "remote" : "local";
  return (
    <div className="fw-field">
      <span className="text-sm font-medium">{t("ipPeerTitle")}</span>
      <p className="text-xs leading-5 text-muted-foreground">
        {use === "local" ? t("ipPeerHelpLocal") : t("ipPeerHelpRemote")}
      </p>
      {use === "local" && (
        <div className="fw-chips">
          {peers.map((p) => (
            <span key={p} className="fw-chip">
              <bdi dir="ltr">{p}</bdi>
            </span>
          ))}
        </div>
      )}
      <CommandBlock text={peerCommand(old, next, other)} />
    </div>
  );
}

export function IPChangeSheet({
  open,
  report,
  initialOld,
  close,
  changed,
}: {
  open: boolean;
  report: AddressReport;
  initialOld: string;
  close: () => void;
  changed: () => Promise<void>;
}) {
  const t = useT();
  const mobile = useIsMobile();
  return (
    <Sheet open={open} onOpenChange={(value) => !value && close()}>
      <SheetContent
        side={mobile ? "bottom" : "right"}
        closeLabel={t("close")}
        className="fw-sheet ip-sheet gap-0"
      >
        {open && (
          <Form
            key={initialOld}
            report={report}
            initialOld={initialOld}
            close={close}
            changed={changed}
          />
        )}
      </SheetContent>
    </Sheet>
  );
}
