// Step 2: where traffic goes — addresses or domains (checked as you type),
// ports when they are not mapped, weights, order (failover priority),
// balancing and the advanced engine options.
import { useContext } from "react";
import { Globe, Loader2, Plus, Trash2, TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { FieldGroup } from "@/components/ui/field";
import { TextField, Choice } from "@/components/shared";
import { ActionButton } from "@/components/help";
import { DragHandle, SortableArea } from "@/components/sortable";
import { useSortableItem } from "@/lib/use-sortable-item";
import { LocaleContext, useT } from "@/lib/i18n";
import { number } from "@/lib/format";
import { isHostname } from "@/lib/ports";
import type { Target } from "@/lib/api";
import { ConnectionAdvanced } from "./ConnectionAdvanced";
import type { ConnectionDraft } from "./useConnectionDraft";

export type DNSPolicy = { every: number; mode: "all" | "first" };

function TargetRow({
  id,
  index,
  target,
  count,
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
  portShown: boolean;
  portText: string;
  resolved?: string[] | null;
  onChange: (next: Target) => void;
  onRemove: () => void;
  onResolve: (host: string) => void;
  onBlurIP: (value: string) => void;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const { setNodeRef, style, dragging, handle } = useSortableItem(id);
  const host = isHostname(target.ip);
  return (
    <li
      ref={setNodeRef}
      style={style}
      className="target-card"
      data-dragging={dragging || undefined}
    >
      <div className="target-card-head">
        {count > 1 ? (
          <DragHandle
            handle={handle}
            label={target.ip || `${t("destination")} ${index + 1}`}
          />
        ) : null}
        <span className="route-index" title={t("targetPriority")}>
          {index + 1}
        </span>
        <span className="flex-1 text-xs font-medium text-muted-foreground">
          {t("destination")} {index + 1}
        </span>
        {count > 1 && (
          <ActionButton
            type="button"
            variant="ghost"
            size="icon"
            label={`${t("removeDestination")} ${index + 1}`}
            onClick={onRemove}
          >
            <Trash2 />
          </ActionButton>
        )}
      </div>
      <FieldGroup
        className="target-fields grid gap-3"
        data-port={portShown || undefined}
        data-weight={count > 1 || undefined}
      >
        <div className="target-host">
          <TextField
            id={`ip-${index}`}
            label={`${t("remoteAddress")}${count > 1 ? ` ${index + 1}` : ""}`}
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
        {count > 1 && (
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
          data-state={
            resolved === undefined
              ? "loading"
              : resolved === null || resolved.length === 0
                ? "bad"
                : "ok"
          }
          aria-live="polite"
        >
          {resolved === undefined ? (
            <Loader2 className="size-3.5 animate-spin" aria-hidden />
          ) : resolved === null || resolved.length === 0 ? (
            <TriangleAlert className="size-3.5" aria-hidden />
          ) : (
            <Globe className="size-3.5" aria-hidden />
          )}
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
  const hosts = value.targets.some((target) => isHostname(target.ip));
  const balancing =
    value.targets.length > 1 || (hosts && policy.mode === "all");
  const portShown = !value.port_mode;
  return (
    <FieldGroup>
      <SortableArea
        ids={ids}
        onMove={(next) =>
          draft.moveTargets(next.map((id) => Number(id.slice(7))))
        }
      >
        <ol className="flex flex-col gap-3" aria-label={t("destinations")}>
          {value.targets.map((target, index) => (
            <TargetRow
              key={ids[index]}
              id={ids[index]}
              index={index}
              target={target}
              count={value.targets.length}
              portShown={portShown}
              portText={portText}
              resolved={isHostname(target.ip) ? resolved[target.ip] : undefined}
              onResolve={onResolve}
              onBlurIP={(v) => draft.parseCombinedIP(index, v)}
              onChange={(next) =>
                patch(
                  "targets",
                  value.targets.map((item, i) => (i === index ? next : item)),
                )
              }
              onRemove={() =>
                patch(
                  "targets",
                  value.targets.filter((_, i) => i !== index),
                )
              }
            />
          ))}
        </ol>
      </SortableArea>
      {value.targets.length > 1 && (
        <p className="text-xs text-muted-foreground">{t("targetOrderHelp")}</p>
      )}
      {value.targets.length < 32 && value.routing === undefined && (
        <Button
          type="button"
          variant="outline"
          className="self-start"
          onClick={draft.addTarget}
        >
          <Plus data-icon="inline-start" />
          {t("addTarget")}
        </Button>
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
            onChange={(next) => onPolicy({ ...policy, every: Number(next) })}
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
      {balancing && capability.strategies.length > 1 && (
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
      <details className="advanced-block">
        <summary>{t("advancedOptions")}</summary>
        <div className="pt-4">
          <ConnectionAdvanced key={value.engine} draft={draft} />
        </div>
      </details>
    </FieldGroup>
  );
}
