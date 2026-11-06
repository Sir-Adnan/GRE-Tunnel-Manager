// Connection editor: three short steps (entrance → destinations → protection
// and review) beside a live route map. On phones it is a full-height sheet
// and the map folds into the summary bar.
import { useRef, useState } from "react";
import { toast } from "sonner";
import { ArrowLeft, ArrowRight, Check } from "lucide-react";
import { EngineGlyph } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogBody,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useDiscardChanges } from "@/lib/use-discard-changes";
import { useT } from "@/lib/i18n";
import { api, type Connection, type Inventory } from "@/lib/api";
import { engineName } from "@/lib/format";
import { isHostname, parseSpans, remoteSpans, spanText } from "@/lib/ports";
import { usePanelRoute } from "@/lib/use-panel-route";
import { useLoaded } from "@/features/operations/hooks";
import type { HealthView } from "@/features/operations/types";
import { useConnectionDraft } from "./useConnectionDraft";
import { EntranceStep } from "./EntranceStep";
import { DestinationsStep, type DNSPolicy } from "./DestinationsStep";
import { ConnectionReview } from "./ConnectionReview";
import { ProtectionFields } from "./ProtectionFields";
import { protectionOf, sameProtection, type Protection } from "./protection";
import { RouteMap } from "./RouteMap";
import { revealInvalidField } from "@/lib/form-validation";

type Props = {
  inventory: Inventory;
  engine: string;
  engines?: string[];
  original?: Connection;
  copy?: Connection;
  onClose: () => void;
  onSubmit: (request: unknown) => Promise<void>;
};

const steps = ["stepEntrance", "stepDestinations", "stepProtection"] as const;
const kernelEngines = ["nftables", "iptables"];

export function ConnectionForm({
  inventory,
  engine,
  engines,
  original,
  copy,
  onClose,
  onSubmit,
}: Props) {
  const t = useT();
  const { navigate } = usePanelRoute();
  const draft = useConnectionDraft({ inventory, engine, original, copy });
  const { value, installed } = draft;
  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const formRef = useRef<HTMLFormElement>(null);
  const health = useLoaded<HealthView>("health", () => 0).value;
  const initialProtection = protectionOf(health?.settings, original?.id);
  const [protection, setProtection] = useState<Protection>();
  const protect = protection || initialProtection;
  const [safeMinutes, setSafeMinutes] = useState(0);
  // Domain lookups: undefined = checking, null = failed, [] = no address.
  const [resolved, setResolved] = useState<
    Record<string, string[] | null | undefined>
  >(() => {
    const known: Record<string, string[]> = {};
    for (const n of inventory.dns || []) known[n.name] = n.addresses;
    return known;
  });
  const firstHost = value.targets.find((x) => isHostname(x.ip))?.ip;
  const stored = inventory.dns?.find((n) => n.name === firstHost);
  const [policy, setPolicy] = useState<DNSPolicy>();
  const dnsPolicy: DNSPolicy = policy || {
    every: stored?.every || 5,
    mode: stored?.mode || "all",
  };
  const { requestClose, confirmation } = useDiscardChanges(
    draft.dirty && !busy,
    onClose,
  );

  async function resolve(host: string) {
    if (resolved[host] !== undefined && resolved[host] !== null) return;
    setResolved((r) => ({ ...r, [host]: undefined }));
    try {
      const family = value.bind.includes(":") ? 6 : 4;
      const out = await api<{ addresses: string[] }>(
        `dns/resolve?name=${encodeURIComponent(host)}&family=${family}`,
      );
      setResolved((r) => ({ ...r, [host]: out.addresses }));
    } catch {
      setResolved((r) => ({ ...r, [host]: null }));
    }
  }

  const kernel = kernelEngines.includes(value.engine);
  const spans = parseSpans(value.ports, kernel).spans;
  const remote = remoteSpans(
    spans,
    value.port_mode || "",
    value.remote_ports || "",
    value.targets[0]?.port || 0,
  );
  const portText =
    value.port_mode === "same"
      ? t("portModeSameShort")
      : remote.spans.map(spanText).join(", ") || "—";
  // Failover needs a kernel forward that ends up with two or more destinations.
  const destinationCount = value.targets.reduce(
    (sum, x) =>
      sum +
      (isHostname(x.ip)
        ? dnsPolicy.mode === "all"
          ? Math.max(1, resolved[x.ip]?.length || 1)
          : 1
        : 1),
    0,
  );
  const failoverEligible = kernel && destinationCount > 1;
  // A domain with several addresses balances even with one destination row:
  // save the method the destinations step shows instead of "single".
  const final: Connection =
    destinationCount > 1 &&
    value.strategy === "single" &&
    draft.capability.strategies.length > 1
      ? { ...value, strategy: draft.capability.strategies[1] }
      : value;
  const unresolved = value.targets.some(
    (x) =>
      isHostname(x.ip) &&
      (resolved[x.ip] === null || resolved[x.ip]?.length === 0),
  );

  /** Checks the current step's fields; focuses the first problem. */
  function validStep() {
    const form = formRef.current;
    if (!form) return true;
    const invalid = form.querySelector<HTMLInputElement>(
      "input:invalid,select:invalid,textarea:invalid",
    );
    if (!invalid) return true;
    setError(t("checkFields"));
    revealInvalidField(invalid, draft.setAdvancedTab);
    return false;
  }

  function next() {
    if (!validStep()) return;
    if (step === 1 && unresolved) {
      setError(t("dnsNoAddressBlock"));
      return;
    }
    setError("");
    setStep((s) => Math.min(s + 1, steps.length - 1));
  }

  async function submit() {
    setBusy(true);
    setError("");
    try {
      const changed = !sameProtection(protect, initialProtection);
      const connection: Connection = { ...final };
      delete connection.resolved;
      await onSubmit({
        action: original ? "update" : "create",
        connection,
        ...(original
          ? { selected: [{ id: original.id, revision: original.revision }] }
          : {}),
        ...(changed || !original ? { protect } : {}),
        ...(safeMinutes ? { safe_minutes: safeMinutes } : {}),
      });
      const hosts = [
        ...new Set(value.targets.map((x) => x.ip).filter(isHostname)),
      ];
      for (const name of hosts) {
        const saved = inventory.dns?.find((n) => n.name === name);
        const wanted = saved
          ? saved.every !== dnsPolicy.every || saved.mode !== dnsPolicy.mode
          : dnsPolicy.every !== 5 || dnsPolicy.mode !== "all";
        if (wanted) {
          try {
            await onSubmit({
              action: "dns-policy",
              dns: {
                policy: { name, every: dnsPolicy.every, mode: dnsPolicy.mode },
              },
            });
          } catch {
            toast.warning(t("savedDNSPolicyFailed"));
            onClose();
            return;
          }
        }
      }
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const map = (
    <RouteMap
      value={value}
      hostname={inventory.host.hostname}
      resolved={Object.fromEntries(
        Object.entries(resolved).map(([k, v]) => [k, v === null ? [] : v]),
      )}
      protection={protect}
      healthOn={Boolean(health?.settings.enabled) || protect.enable_health}
      safeMinutes={safeMinutes}
    />
  );
  return (
    <>
      <Dialog open onOpenChange={(open) => !open && !busy && requestClose()}>
        <DialogContent
          closeLabel={t("close")}
          scrollLayout="body"
          className="dialog-shell connection-editor sm:max-w-5xl"
          onEscapeKeyDown={(event) => busy && event.preventDefault()}
        >
          <DialogHeader>
            <div className="flex items-center gap-3">
              <span className="engine-icon is-primary">
                <EngineGlyph engine={value.engine} />
              </span>
              <div className="min-w-0">
                <DialogTitle>
                  {t(
                    original
                      ? "edit"
                      : copy
                        ? "duplicateConnection"
                        : "newConnection",
                  )}
                </DialogTitle>
                <DialogDescription>
                  <bdi>{engineName(value.engine)}</bdi> ·{" "}
                  {inventory.host.hostname}
                </DialogDescription>
              </div>
            </div>
            <ol className="form-steps" aria-label={t("connectionSections")}>
              {steps.map((key, index) => (
                <li
                  key={key}
                  aria-current={index === step ? "step" : undefined}
                  data-state={
                    index < step ? "done" : index === step ? "current" : "next"
                  }
                >
                  <button
                    type="button"
                    className="form-step-button"
                    disabled={index > step}
                    onClick={() => index < step && setStep(index)}
                  >
                    <span className="form-step-index">
                      {index < step ? <Check /> : index + 1}
                    </span>
                    {t(key)}
                  </button>
                </li>
              ))}
            </ol>
          </DialogHeader>
          <DialogBody key={step}>
            <div className="connection-editor-grid">
              <div className="min-w-0">
                {error && (
                  <Alert variant="destructive" role="alert" className="mb-4">
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                )}
                {!installed && (
                  <Alert className="mb-4">
                    <AlertDescription>{t("needsInstall")}</AlertDescription>
                  </Alert>
                )}
                <form
                  ref={formRef}
                  id="connection-form"
                  noValidate
                  onInput={(event) => {
                    const input = event.target as HTMLInputElement;
                    input.removeAttribute("aria-invalid");
                    input
                      .closest("[data-slot=field]")
                      ?.removeAttribute("data-invalid");
                  }}
                  onSubmit={(event) => {
                    event.preventDefault();
                    if (step < steps.length - 1) next();
                    else void submit();
                  }}
                >
                  {step === 0 && (
                    <EntranceStep
                      draft={draft}
                      inventory={inventory}
                      engines={engines}
                      editing={Boolean(original)}
                    />
                  )}
                  {step === 1 && (
                    <DestinationsStep
                      draft={draft}
                      resolved={resolved}
                      onResolve={(host) => void resolve(host)}
                      policy={dnsPolicy}
                      onPolicy={setPolicy}
                      portText={portText}
                    />
                  )}
                  {step === 2 && (
                    <div className="flex flex-col gap-5">
                      <ProtectionFields
                        settings={health?.settings}
                        value={protect}
                        onChange={setProtection}
                        failoverEligible={failoverEligible}
                        failoverHint={
                          kernel ? undefined : t("protectFailoverRelay")
                        }
                        safeMinutes={safeMinutes}
                        onSafeMinutes={setSafeMinutes}
                        onAdvanced={() => navigate("health", { settings: "1" })}
                      />
                      <ConnectionReview value={final} resolved={resolved} />
                    </div>
                  )}
                </form>
              </div>
              <div className="connection-editor-aside">{map}</div>
            </div>
          </DialogBody>
          <DialogFooter layout="summary" className="connection-editor-footer">
            <div className="min-w-0 flex-1 text-xs text-muted-foreground">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline">{value.protocol.toUpperCase()}</Badge>
                <bdi className="truncate font-mono" dir="ltr">
                  {value.ports || "—"}
                </bdi>
                <ArrowRight className="size-3 rtl:rotate-180" />
                <span>
                  {t("destinations")}: {value.targets.length}
                </span>
              </div>
              <p className="mt-1">
                {t(value.enabled ? "willStart" : "willSaveDisabled")}
              </p>
            </div>
            <div className="flex shrink-0 gap-2">
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => (step ? setStep(step - 1) : requestClose())}
              >
                {step > 0 && (
                  <ArrowLeft
                    data-icon="inline-start"
                    className="rtl:rotate-180"
                  />
                )}
                {t(step ? "back" : "cancel")}
              </Button>
              {step === steps.length - 1 ? (
                <Button
                  type="submit"
                  form="connection-form"
                  disabled={busy || !installed}
                >
                  <Check data-icon="inline-start" />
                  {t(busy ? "working" : "save")}
                </Button>
              ) : (
                <Button
                  type="submit"
                  form="connection-form"
                  disabled={!installed}
                >
                  {t("next")}
                  <ArrowRight
                    data-icon="inline-end"
                    className="rtl:rotate-180"
                  />
                </Button>
              )}
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {confirmation}
    </>
  );
}
