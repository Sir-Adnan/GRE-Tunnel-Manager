import { useState } from "react";
import type { FormEvent } from "react";
import {
  ArrowLeftRight,
  Check,
  CircleAlert,
  Copy,
  Globe,
  LoaderCircle,
  Server,
  Users,
} from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { FieldGroup, Field, FieldLabel } from "@/components/ui/field";
import { Switch } from "@/components/ui/switch";
import { Choice, TextField } from "@/components/shared";
import { ActionButton } from "@/components/help";
import { CommandBlock } from "@/components/CommandBlock";
import { ErrorExplain } from "@/components/ErrorExplain";
import type { Inventory } from "@/lib/api";
import { creationOptions } from "@/lib/creation-defaults";
import { errorMessage, useT } from "@/lib/i18n";
import { useCopyText } from "@/lib/use-copy-text";
import { useDiscardChanges } from "@/lib/use-discard-changes";
import {
  defaultName,
  farSide,
  forwardConnection,
  greRequest,
  maxMTU,
  tunnelAddresses,
  wizardDefaults,
  wizardErrors,
} from "./model";
import type { Protocol, WizardDraft, WizardErrors } from "./model";

const steps = ["wizStepTunnel", "wizStepForward", "wizStepReview"] as const;
const installCommand =
  "curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh | sudo bash";

type Task = "tunnel" | "forward";
type TaskState = "waiting" | "running" | "done" | "failed";

/**
 * Connects this server to a foreign one: a GRE tunnel, then a kernel forward
 * of public ports through it. Each part is one ordinary broker operation; a
 * failed forward can be retried without creating the tunnel again.
 */
export function TwoServerWizard({
  inventory,
  run,
  onClose,
  onDone,
}: {
  inventory: Inventory;
  run: (request: unknown) => Promise<void>;
  onClose: () => void;
  /** Opens the Health page after a successful setup. */
  onDone: () => void;
}) {
  const t = useT();
  const [draft, setDraft] = useState<WizardDraft>(() =>
    wizardDefaults(inventory),
  );
  const [baseline] = useState(() => JSON.stringify(draft));
  const [step, setStep] = useState(0);
  const [errors, setErrors] = useState<WizardErrors>({});
  const [tasks, setTasks] = useState<Partial<Record<Task, TaskState>>>({});
  const [failure, setFailure] = useState("");
  const running = Object.values(tasks).includes("running");
  const started = Object.keys(tasks).length > 0;
  const finished =
    tasks.tunnel === "done" && (!draft.forward || tasks.forward === "done");
  const { requestClose, confirmation } = useDiscardChanges(
    JSON.stringify(draft) !== baseline && !finished,
    onClose,
  );
  const ends = tunnelAddresses(draft.id);
  const far = farSide(draft);
  const change = <K extends keyof WizardDraft>(
    key: K,
    value: WizardDraft[K],
  ) => {
    setDraft((current) => ({ ...current, [key]: value }));
    setErrors((current) => ({ ...current, [key]: undefined }));
  };
  const error = (field: keyof WizardErrors) =>
    errors[field] ? t(errors[field]) : undefined;

  function next(event: FormEvent) {
    event.preventDefault();
    if (step < 2) {
      const found = wizardErrors(draft, inventory, step as 0 | 1);
      setErrors(found);
      const first = Object.keys(found)[0];
      if (first) {
        document.getElementById(`wiz-${first}`)?.focus();
        return;
      }
      setStep(step + 1);
      return;
    }
    void create();
  }

  async function create() {
    setFailure("");
    // A tunnel created by an earlier attempt is not created again.
    const order: Task[] = [
      ...(tasks.tunnel === "done" ? [] : (["tunnel"] as Task[])),
      ...(draft.forward ? (["forward"] as Task[]) : []),
    ];
    for (const task of order) {
      setTasks((current) => ({ ...current, [task]: "running" }));
      try {
        await run(
          task === "tunnel"
            ? { action: "gre-create", gre: greRequest(draft) }
            : {
                action: "create",
                connection: forwardConnection(
                  draft,
                  inventory,
                  creationOptions,
                ),
              },
        );
        setTasks((current) => ({ ...current, [task]: "done" }));
      } catch (e) {
        setTasks((current) => ({ ...current, [task]: "failed" }));
        setFailure(errorMessage(e));
        return;
      }
    }
  }

  const taskRows: [Task, string, string][] = [
    [
      "tunnel",
      "wizTaskTunnel",
      `GRE ${draft.id} · ${ends.entrance} ⇄ ${ends.foreign}`,
    ],
    ...(draft.forward
      ? ([
          ["forward", "wizTaskForward", `${draft.ports} → ${ends.foreign}`],
        ] as [Task, string, string][])
      : []),
  ];

  return (
    <>
      <Dialog open onOpenChange={(open) => !open && !running && requestClose()}>
        <DialogContent
          closeLabel={t("close")}
          scrollLayout="body"
          className="dialog-shell sm:max-w-3xl"
        >
          <DialogHeader>
            <DialogTitle>{t("wizTitle")}</DialogTitle>
            <DialogDescription>{t("wizIntro")}</DialogDescription>
            {!started && (
              <ol className="form-steps" aria-label={t("wizTitle")}>
                {steps.map((key, index) => (
                  <li
                    key={key}
                    aria-current={index === step ? "step" : undefined}
                    data-state={
                      index < step
                        ? "done"
                        : index === step
                          ? "current"
                          : "next"
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
                      <span className="form-step-label">{t(key)}</span>
                    </button>
                  </li>
                ))}
              </ol>
            )}
          </DialogHeader>
          <form
            id="two-server-wizard"
            className="flex min-h-0 flex-1 flex-col overflow-hidden"
            onSubmit={next}
            noValidate
          >
            <DialogBody key={started ? "run" : step}>
              {started ? (
                <div className="flex flex-col gap-4">
                  <ol className="wizard-tasks">
                    {taskRows.map(([task, label, detail]) => (
                      <li key={task} data-state={tasks[task] ?? "waiting"}>
                        <span className="wizard-task-icon" aria-hidden>
                          {tasks[task] === "running" ? (
                            <LoaderCircle className="animate-spin" />
                          ) : tasks[task] === "done" ? (
                            <Check />
                          ) : tasks[task] === "failed" ? (
                            <CircleAlert />
                          ) : null}
                        </span>
                        <span className="flex min-w-0 flex-col">
                          <span className="font-medium">{t(label)}</span>
                          <bdi dir="ltr" className="wizard-task-detail">
                            {detail}
                          </bdi>
                        </span>
                        <span className="sr-only">
                          {t(`wizTask_${tasks[task] ?? "waiting"}`)}
                        </span>
                      </li>
                    ))}
                  </ol>
                  {failure && (
                    <div className="flex flex-col gap-2">
                      <p className="text-sm font-medium">
                        {t(
                          tasks.tunnel === "done"
                            ? "wizForwardFailed"
                            : "wizTunnelFailed",
                        )}
                      </p>
                      <ErrorExplain error={failure} onNavigate={onClose} />
                    </div>
                  )}
                  {finished && (
                    <Alert role="status">
                      <AlertDescription>{t("wizDone")}</AlertDescription>
                    </Alert>
                  )}
                  {finished && <FarSide far={far} />}
                </div>
              ) : step === 0 ? (
                <FieldGroup className="md:grid md:grid-cols-2">
                  <TextField
                    id="wiz-remote"
                    label={t("wizRemote")}
                    description={t("wizRemoteHelp")}
                    dir="ltr"
                    inputMode="decimal"
                    autoComplete="off"
                    placeholder="198.51.100.20"
                    value={draft.remote}
                    error={error("remote")}
                    onChange={(e) => change("remote", e.target.value)}
                    autoFocus
                  />
                  {inventory.host.addresses.length > 1 ? (
                    <Choice
                      id="wiz-bind"
                      label={t("wizBind")}
                      description={t("wizBindHelp")}
                      value={draft.bind}
                      onChange={(value) => change("bind", value)}
                      choices={inventory.host.addresses.map((ip) => ({
                        value: ip,
                        label: ip,
                      }))}
                    />
                  ) : (
                    <TextField
                      id="wiz-bind"
                      label={t("wizBind")}
                      description={t("wizBindHelp")}
                      dir="ltr"
                      value={draft.bind}
                      error={error("bind")}
                      onChange={(e) => change("bind", e.target.value)}
                    />
                  )}
                  <TextField
                    id="wiz-id"
                    label={t("tunnelID")}
                    description={t("wizIDHelp")}
                    type="number"
                    min={1}
                    max={250}
                    value={draft.id || ""}
                    error={error("id")}
                    onChange={(e) => change("id", Number(e.target.value))}
                  />
                  <TextField
                    id="wiz-mtu"
                    label={t("mtu")}
                    description={t("wizMTUHelp").replace(
                      "{max}",
                      String(maxMTU(draft.remote)),
                    )}
                    type="number"
                    min={1280}
                    max={maxMTU(draft.remote)}
                    value={draft.mtu || ""}
                    error={error("mtu")}
                    onChange={(e) => change("mtu", Number(e.target.value))}
                  />
                </FieldGroup>
              ) : step === 1 ? (
                <FieldGroup>
                  <Field orientation="horizontal" className="wizard-switch">
                    <Switch
                      id="wiz-forward"
                      checked={draft.forward}
                      onCheckedChange={(on) => change("forward", on)}
                    />
                    <FieldLabel
                      htmlFor="wiz-forward"
                      className="flex-col items-start gap-0.5"
                    >
                      <span>{t("wizForward")}</span>
                      <span className="text-xs font-normal text-muted-foreground">
                        {t("wizForwardHelp")}
                      </span>
                    </FieldLabel>
                  </Field>
                  {draft.forward && (
                    <FieldGroup className="md:grid md:grid-cols-2">
                      <TextField
                        id="wiz-ports"
                        label={t("wizPorts")}
                        description={t("wizPortsHelp")}
                        dir="ltr"
                        inputMode="numeric"
                        value={draft.ports}
                        error={error("ports")}
                        onChange={(e) => change("ports", e.target.value)}
                        autoFocus
                      />
                      <Choice
                        id="wiz-protocol"
                        label={t("protocol")}
                        value={draft.protocol}
                        onChange={(value) =>
                          change("protocol", value as Protocol)
                        }
                        choices={[
                          { value: "both", label: "TCP + UDP" },
                          { value: "tcp", label: "TCP" },
                          { value: "udp", label: "UDP" },
                        ]}
                      />
                      <TextField
                        id="wiz-name"
                        label={t("name")}
                        optional
                        maxLength={40}
                        dir="ltr"
                        description={t("wizNameHelp")}
                        placeholder={defaultName(
                          draft.id,
                          draft.ports.replace(/\s+/g, ""),
                        )}
                        value={draft.name}
                        error={error("name")}
                        onChange={(e) => change("name", e.target.value)}
                      />
                    </FieldGroup>
                  )}
                </FieldGroup>
              ) : (
                <div className="flex flex-col gap-5">
                  <WizardRoute draft={draft} />
                  <FarSide far={far} />
                </div>
              )}
            </DialogBody>
          </form>
          <DialogFooter>
            {finished ? (
              <>
                <Button variant="outline" onClick={onClose}>
                  {t("close")}
                </Button>
                <Button onClick={onDone}>{t("wizOpenHealth")}</Button>
              </>
            ) : started ? (
              <Button
                type="button"
                disabled={running}
                onClick={() => void create()}
              >
                {running ? t("working") : t("wizRetry")}
              </Button>
            ) : (
              <>
                {step > 0 && (
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setStep(step - 1)}
                  >
                    {t("back")}
                  </Button>
                )}
                <Button type="submit" form="two-server-wizard">
                  {step < 2 ? t("next") : t("wizCreate")}
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {confirmation}
    </>
  );
}

/** Users → this server → tunnel → foreign server, with the addresses each hop uses. */
function WizardRoute({ draft }: { draft: WizardDraft }) {
  const t = useT();
  const ends = tunnelAddresses(draft.id);
  const hops = [
    {
      icon: Users,
      title: t("wizHopUsers"),
      detail: draft.forward ? `:${draft.ports}` : "—",
    },
    {
      icon: Server,
      title: t("wizHopHere"),
      detail: draft.bind,
      inner: ends.entrance,
    },
    {
      icon: Globe,
      title: t("wizHopForeign"),
      detail: draft.remote,
      inner: ends.foreign,
    },
  ];
  return (
    <section aria-label={t("wizRoute")} className="wizard-route">
      {hops.map((hop, index) => (
        <div key={hop.title} className="contents">
          {index > 0 && (
            <span className="wizard-link" aria-hidden>
              {index === 2 ? (
                <>
                  <ArrowLeftRight />
                  <span dir="ltr">GRE {draft.id}</span>
                </>
              ) : (
                <ArrowLeftRight />
              )}
            </span>
          )}
          <div className="wizard-hop">
            <hop.icon aria-hidden />
            <strong>{hop.title}</strong>
            <bdi dir="ltr">{hop.detail}</bdi>
            {hop.inner && (
              <bdi dir="ltr" className="wizard-inner">
                {hop.inner}
              </bdi>
            )}
          </div>
        </div>
      ))}
      <p className="wizard-route-note">
        {draft.forward
          ? t("wizRouteForward")
              .replace("{ports}", draft.ports)
              .replace("{ip}", ends.foreign)
          : t("wizRouteTunnelOnly")}
      </p>
    </section>
  );
}

/** The values to enter on the foreign server, each copyable. */
function FarSide({ far }: { far: ReturnType<typeof farSide> }) {
  const t = useT();
  const rows: [string, string][] = [
    ["tunnelID", String(far.id)],
    ["role", "Kharej / Side A"],
    ["peerIP", far.remote],
    ["bind", far.bind],
    ["mtu", String(far.mtu)],
  ];
  return (
    <section className="wizard-far" aria-labelledby="wizard-far-title">
      <h3 id="wizard-far-title">{t("wizFarTitle")}</h3>
      <ol className="wizard-far-steps">
        <li>
          <p>{t("wizFarInstall")}</p>
          <CommandBlock text={installCommand} />
        </li>
        <li>
          <p>{t("wizFarGRE")}</p>
          <dl className="wizard-far-values">
            {rows.map(([key, value]) => (
              <div key={key}>
                <dt>{t(key)}</dt>
                <dd>
                  <bdi dir="ltr">{value}</bdi>
                  {key !== "role" && <CopyValue text={value} label={t(key)} />}
                </dd>
              </div>
            ))}
          </dl>
        </li>
        <li>
          <p>{t("wizFarFirewall")}</p>
        </li>
      </ol>
    </section>
  );
}

/** An icon button that copies one value. */
function CopyValue({ text, label }: { text: string; label: string }) {
  const t = useT();
  const { status, copy } = useCopyText(text);
  return (
    <ActionButton
      type="button"
      variant="ghost"
      size="icon-xs"
      label={
        status === "copied"
          ? t("copied")
          : t("wizCopy").replace("{name}", label)
      }
      onClick={() => void copy()}
    >
      {status === "copied" ? <Check /> : <Copy />}
    </ActionButton>
  );
}
