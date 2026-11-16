// Step 2: where traffic goes — addresses or domains (checked as you type),
// ports when they are not mapped, weights, order (failover priority),
// balancing and the advanced engine options. With several destinations each
// one is a compact, numbered row that opens to edit; its handle or its ⋯ menu
// changes the order.
import { useContext, useState } from "react";
import {
  ChevronDown,
  Globe,
  Loader2,
  Plus,
  Server,
  SlidersHorizontal,
  Split,
  Trash2,
  TriangleAlert,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { FieldGroup } from "@/components/ui/field";
import { TextField, Choice } from "@/components/shared";
import { ActionMenu } from "@/components/ActionMenu";
import { FormSection } from "@/components/FormSection";
import { DragHandle, SortableArea } from "@/components/sortable";
import { useMoveBy, useSortableItem } from "@/lib/use-sortable-item";
import { moveActions } from "@/lib/move-actions";
import { LocaleContext, useT } from "@/lib/i18n";
import { number } from "@/lib/format";
import { isHostname, targetPorts } from "@/lib/ports";
import type { Target } from "@/lib/api";
import { ConnectionAdvanced } from "./ConnectionAdvanced";
import type { ConnectionDraft } from "./useConnectionDraft";

export type DNSPolicy = { every: number; mode: "all" | "first" };

type Lookup = string[] | null | undefined;
const lookupState = (resolved: Lookup) =>
  resolved === undefined
    ? "loading"
    : resolved === null || resolved.length === 0
      ? "bad"
      : "ok";

function LookupIcon({ resolved }: { resolved: Lookup }) {
  const state = lookupState(resolved);
  return state === "loading" ? (
    <Loader2 className="size-3.5 animate-spin" aria-hidden />
  ) : state === "bad" ? (
    <TriangleAlert className="size-3.5" aria-hidden />
  ) : (
    <Globe className="size-3.5" aria-hidden />
  );
}

/** A row the browser could not check while closed stays open. */
function incomplete(target: Target, portShown: boolean, several: boolean) {
  const inRange = (n: number, max: number) =>
    Number.isInteger(n) && n >= 1 && n <= max;
  return (
    !target.ip ||
    (portShown && !inRange(target.port, 65535)) ||
    (several && !inRange(target.weight, 256))
  );
}

function TargetRow({
  id,
  index,
  target,
  count,
  failover,
  open,
  onOpenChange,
  portShown,
  portText,
  resolved,
  onChange,
  onRemove,
  onResolve,
  onBlurIP,
}: {
  id: string;
  index: number;
  target: Target;
  count: number;
  /** Primary + backup: the order is the failover priority. */
  failover: boolean;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  portShown: boolean;
  portText: string;
  resolved?: Lookup;
  onChange: (next: Target) => void;
  onRemove: () => void;
  onResolve: (host: string) => void;
  onBlurIP: (value: string) => void;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const { setNodeRef, style, dragging, handle } = useSortableItem(id);
  const moveBy = useMoveBy();
  const host = isHostname(target.ip);
  const several = count > 1;
  const name = `${t("destination")} ${number(index + 1, locale)}`;
  const address = !target.ip
    ? ""
    : !portShown
      ? target.ip
      : target.ip.includes(":")
        ? `[${target.ip}]:${targetPorts(target)}`
        : `${target.ip}:${targetPorts(target)}`;
  const fieldsId = `target-fields-${index}`;
  const fields = (
    <div id={fieldsId} className="target-body">
      <FieldGroup
        className="target-fields grid gap-3"
        data-port={portShown || undefined}
        data-weight={several || undefined}
      >
        <div className="target-host">
          <TextField
            id={`ip-${index}`}
            label={`${t("remoteAddress")}${several ? ` ${index + 1}` : ""}`}
            placeholder="198.51.100.20 · backend.example.com"
            dir="ltr"
            value={target.ip}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            onChange={(event) =>
              onChange({ ...target, ip: event.target.value.trim() })
            }
            onBlur={(event) => {
              const v = event.target.value.trim().toLowerCase();
              onBlurIP(v);
              if (isHostname(v)) onResolve(v);
            }}
            required
            maxLength={253}
          />
        </div>
        {portShown && (
          <TextField
            id={`port-${index}`}
            label={t("remotePort")}
            type="number"
            min={1}
            max={65535}
            dir="ltr"
            value={target.port}
            onChange={(event) =>
              onChange({
                ...target,
                port: Number(event.target.value),
                port_last: undefined,
              })
            }
            required
          />
        )}
        {several && (
          <div className="min-w-0">
            <TextField
              id={`weight-${index}`}
              label={t("weight")}
              help={t("weightHelp")}
              type="number"
              min={1}
              max={256}
              required
              dir="ltr"
              value={target.weight}
              onChange={(event) =>
                onChange({ ...target, weight: Number(event.target.value) })
              }
            />
          </div>
        )}
      </FieldGroup>
      {!portShown && (
        <p className="text-xs text-muted-foreground" dir="auto">
          {t("remotePort")}:{" "}
          <bdi dir="ltr" className="font-mono">
            {portText}
          </bdi>
        </p>
      )}
      {host && (
        <p
          className="dns-preview"
          data-state={lookupState(resolved)}
          aria-live="polite"
        >
          <LookupIcon resolved={resolved} />
          <span className="min-w-0">
            {resolved === undefined
              ? t("dnsChecking")
              : resolved === null || resolved.length === 0
                ? t("dnsNoAddress")
                : t("dnsResolves").replace(
                    "{n}",
                    number(resolved.length, locale),
                  )}
            {resolved && resolved.length > 0 && (
              <bdi dir="ltr" className="ms-1 font-mono">
                {resolved.join(", ")}
              </bdi>
            )}
          </span>
        </p>
      )}
    </div>
  );
  if (!several) return <li className="target-single">{fields}</li>;
  return (
    <li
      ref={setNodeRef}
      style={style}
      className="target-row"
      data-dragging={dragging || undefined}
      data-open={open || undefined}
    >
      <div className="target-summary">
        <DragHandle handle={handle} label={target.ip || name} />
        <span className="reorder-pos" title={t("targetPriority")} aria-hidden>
          {number(index + 1, locale)}
        </span>
        <button
          type="button"
          className="target-toggle"
          aria-expanded={open}
          aria-controls={open ? fieldsId : undefined}
          aria-label={`${t("editDestination")}: ${target.ip || name}`}
          onClick={() => onOpenChange(!open)}
        >
          {failover && (
            <span
              className="target-role"
              data-primary={index === 0 || undefined}
            >
              {t(index === 0 ? "primaryTarget" : "backupTarget")}
            </span>
          )}
          <span className="target-address">
            {address ? (
              <bdi dir="ltr" className="truncate font-mono">
                {address}
              </bdi>
            ) : (
              <span className="truncate text-muted-foreground">
                {t("targetNoAddress")}
              </span>
            )}
            <span className="target-meta">
              {host && (
                <span
                  className="dns-preview"
                  data-state={lookupState(resolved)}
                >
                  <LookupIcon resolved={resolved} />
                </span>
              )}
              {t("weight")}{" "}
              <bdi dir="ltr" className="font-mono">
                {target.weight}
              </bdi>
            </span>
          </span>
          <ChevronDown className="target-chevron" aria-hidden />
        </button>
        <ActionMenu
          label={`${t("destinationActions")}: ${target.ip || name}`}
          title={target.ip || name}
          groups={[
            moveActions(t, (delta) => moveBy?.(id, delta), index, count),
            [
              {
                id: "remove",
                label: t("removeDestination"),
                icon: <Trash2 />,
                destructive: true,
                onSelect: onRemove,
              },
            ],
          ]}
        />
      </div>
      {open && fields}
    </li>
  );
}

export function DestinationsStep({
  draft,
  resolved,
  onResolve,
  policy,
  onPolicy,
  portText,
}: {
  draft: ConnectionDraft;
  resolved: Record<string, string[] | null | undefined>;
  onResolve: (host: string) => void;
  policy: DNSPolicy;
  onPolicy: (next: DNSPolicy) => void;
  /** The remote port(s) when they follow the local ports (same or mapped). */
  portText: string;
}) {
  const t = useT();
  const { value, patch, capability } = draft;
  const ids = value.targets.map((_, i) => `target-${i}`);
  const several = value.targets.length > 1;
  // Open rows, by index. A row that is not complete opens and stays open
  // until the person closes it, so a required field is never hidden and a
  // row never closes while its address is typed.
  const [opened, setOpened] = useState<number[]>([]);
  const missing = value.targets.flatMap((target, index) =>
    !opened.includes(index) && incomplete(target, !value.port_mode, several)
      ? [index]
      : [],
  );
  if (missing.length) setOpened([...opened, ...missing]);
  const isOpen = (index: number) =>
    opened.includes(index) || missing.includes(index);
  const setOpen = (index: number, open: boolean) =>
    setOpened((current) =>
      open ? [...current, index] : current.filter((i) => i !== index),
    );
  function move(order: number[]) {
    setOpened((current) =>
      order.flatMap((from, to) => (current.includes(from) ? [to] : [])),
    );
    draft.moveTargets(order);
  }
  function remove(index: number) {
    setOpened((current) =>
      current.filter((i) => i !== index).map((i) => (i > index ? i - 1 : i)),
    );
    patch(
      "targets",
      value.targets.filter((_, i) => i !== index),
    );
  }
  // A new row opens alone; finished rows fold so the list stays short.
  function add() {
    setOpened([value.targets.length]);
    draft.addTarget();
  }
  const hosts = value.targets.some((target) => isHostname(target.ip));
  const balancing =
    value.targets.length > 1 || (hosts && policy.mode === "all");
  const portShown = !value.port_mode;
  const strategyShown = balancing && capability.strategies.length > 1;
  return (
    <div className="form-sections">
      <FormSection
        icon={<Server />}
        title={t("stepDestinations")}
        description={t("sectionTargetsHelp")}
      >
        <SortableArea
          ids={ids}
          onMove={(next) => move(next.map((id) => Number(id.slice(7))))}
        >
          <ol
            className="target-list"
            data-several={several || undefined}
            aria-label={t("destinations")}
          >
            {value.targets.map((target, index) => (
              <TargetRow
                key={ids[index]}
                id={ids[index]}
                index={index}
                target={target}
                count={value.targets.length}
                failover={value.strategy === "failover"}
                open={isOpen(index)}
                onOpenChange={(open) => setOpen(index, open)}
                portShown={portShown}
                portText={portText}
                resolved={
                  isHostname(target.ip) ? resolved[target.ip] : undefined
                }
                onResolve={onResolve}
                onBlurIP={(v) => draft.parseCombinedIP(index, v)}
                onChange={(next) =>
                  patch(
                    "targets",
                    value.targets.map((item, i) => (i === index ? next : item)),
                  )
                }
                onRemove={() => remove(index)}
              />
            ))}
          </ol>
        </SortableArea>
        {value.targets.length > 1 && (
          <p className="field-hint">{t("targetOrderHelp")}</p>
        )}
        {value.targets.length < 32 && value.routing === undefined && (
          <Button
            type="button"
            variant="outline"
            className="self-start"
            onClick={add}
          >
            <Plus data-icon="inline-start" />
            {t("addTarget")}
          </Button>
        )}
      </FormSection>
      {(hosts || strategyShown) && (
        <FormSection
          icon={<Split />}
          title={t("sectionSpread")}
          description={t("sectionSpreadHelp")}
        >
          {strategyShown && (
            <Choice
              id="strategy"
              label={t("strategy")}
              help={t("strategyHelp")}
              value={
                value.strategy === "single"
                  ? capability.strategies[1]
                  : value.strategy
              }
              choices={capability.strategies
                .filter((s) => s !== "single")
                .map((s) => ({ value: s, label: t(s) }))}
              onChange={(next) => patch("strategy", next)}
            />
          )}
          {hosts && (
            <FieldGroup columns className="dns-policy">
              <Choice
                id="dns-every"
                label={t("dnsRefresh")}
                help={t("dnsRefreshHelp")}
                value={String(policy.every)}
                choices={[1, 2, 5, 10, 15, 30, 60].map((m) => ({
                  value: String(m),
                  label: t("dnsEvery").replace("{n}", String(m)),
                }))}
                onChange={(next) =>
                  onPolicy({ ...policy, every: Number(next) })
                }
              />
              <Choice
                id="dns-mode"
                label={t("dnsMode")}
                help={t("dnsModeHelp")}
                value={policy.mode}
                choices={[
                  { value: "all", label: t("dnsModeAll") },
                  { value: "first", label: t("dnsModeFirst") },
                ]}
                onChange={(next) =>
                  onPolicy({ ...policy, mode: next as DNSPolicy["mode"] })
                }
              />
            </FieldGroup>
          )}
        </FormSection>
      )}
      <details className="advanced-block">
        <summary>
          <span className="form-section-icon" aria-hidden>
            <SlidersHorizontal />
          </span>
          {t("advancedOptions")}
        </summary>
        <div className="pt-1">
          <ConnectionAdvanced key={value.engine} draft={draft} />
        </div>
      </details>
    </div>
  );
}
