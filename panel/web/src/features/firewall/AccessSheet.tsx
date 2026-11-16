// Who may use one connection: everyone, only listed sources or everyone but
// them, plus per-source limits. Edits go into the page draft; Apply saves.
import { useState } from "react";
import { TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { HelpTip } from "@/components/help";
import { Segmented } from "@/components/Segmented";
import { useIsMobile } from "@/hooks/use-mobile";
import { useT } from "@/lib/i18n";
import {
  accessProblem,
  parseSources,
  type AccessMode,
  type FirewallAccess,
  type FirewallConnection,
} from "./model";
import { fill } from "./text";

const limit = (value: string) =>
  Math.min(100000, Math.max(0, Math.trunc(Number(value) || 0)));

function Editor({
  connection,
  initial,
  save,
  close,
}: {
  connection: FirewallConnection;
  initial: FirewallAccess;
  save: (access: FirewallAccess) => void;
  close: () => void;
}) {
  const t = useT();
  const [mode, setMode] = useState<AccessMode>(initial.mode);
  const [text, setText] = useState(initial.sources.join("\n"));
  const [perIP, setPerIP] = useState(String(initial.per_ip || ""));
  const [rate, setRate] = useState(String(initial.rate || ""));
  const { sources, invalid } = parseSources(text);
  const next: FirewallAccess = {
    id: connection.id,
    mode,
    sources,
    per_ip: limit(perIP),
    rate: limit(rate),
  };
  const problem = invalid.length
    ? { key: "fwSourcesInvalid", vars: { s: invalid.slice(0, 3).join(", ") } }
    : accessProblem(next, connection.bind);
  const ports = `${connection.ports}/${connection.protocol === "both" ? "tcp+udp" : connection.protocol}`;
  return (
    <form
      className="flex min-h-0 flex-1 flex-col"
      onSubmit={(event) => {
        event.preventDefault();
        if (!problem) save(next);
      }}
    >
      <SheetHeader>
        <SheetTitle>
          {fill(t("fwAccessTitle"), { n: connection.name || connection.id })}
        </SheetTitle>
        <SheetDescription>
          {t("fwAccessIntro").split("{p}")[0]}
          <bdi dir="ltr" className="font-mono">
            {ports}
          </bdi>
          {t("fwAccessIntro").split("{p}")[1]}
        </SheetDescription>
      </SheetHeader>
      <div className="fw-sheet-body">
        <div className="fw-field">
          <span className="text-sm font-medium" id="fw-mode-label">
            {t("fwMode")}
          </span>
          <Segmented
            label={t("fwMode")}
            value={mode}
            onChange={(v) => setMode(v as AccessMode)}
            options={(["off", "allow", "deny"] as const).map((v) => ({
              value: v,
              label: t(`fwMode_${v}`),
            }))}
          />
        </div>
        {mode !== "off" && (
          <div className="fw-field">
            <div className="field-label-row">
              <label htmlFor="fw-sources" className="text-sm font-medium">
                {t("fwSources")}
              </label>
              <HelpTip label={`${t("fwSources")} · ?`}>
                {t("fwSourcesHelp")}
              </HelpTip>
            </div>
            <textarea
              id="fw-sources"
              dir="ltr"
              rows={5}
              spellCheck={false}
              className="dns-textarea"
              value={text}
              aria-invalid={Boolean(problem)}
              aria-describedby={problem ? "fw-sources-error" : undefined}
              placeholder={"203.0.113.7\n198.51.100.0/24"}
              onChange={(event) => setText(event.target.value)}
            />
            {problem && (
              <p
                id="fw-sources-error"
                className="text-xs text-destructive"
                role="alert"
              >
                {fill(t(problem.key), problem.vars)}
              </p>
            )}
            {mode === "allow" && (
              <p className="fw-note">
                <TriangleAlert className="size-3.5 shrink-0" aria-hidden />
                {t("fwLockoutWarn")}
              </p>
            )}
          </div>
        )}
        <div className="fw-limits">
          {(
            [
              ["fw-per-ip", "fwPerIP", "fwPerIPHelp", perIP, setPerIP],
              ["fw-rate", "fwRate", "fwRateHelp", rate, setRate],
            ] as const
          ).map(([id, label, help, value, set]) => (
            <div key={id} className="fw-field">
              <div className="field-label-row">
                <label htmlFor={id} className="text-sm font-medium">
                  {t(label)}
                </label>
                <HelpTip label={`${t(label)} · ?`}>{t(help)}</HelpTip>
              </div>
              <Input
                id={id}
                type="number"
                inputMode="numeric"
                min={0}
                max={100000}
                dir="ltr"
                placeholder="0"
                value={value}
                onChange={(event) => set(event.target.value)}
              />
            </div>
          ))}
        </div>
      </div>
      <SheetFooter className="fw-sheet-footer flex-row justify-end border-t">
        <Button type="button" variant="outline" onClick={close}>
          {t("cancel")}
        </Button>
        <Button type="submit" disabled={Boolean(problem)}>
          {t("fwDone")}
        </Button>
      </SheetFooter>
    </form>
  );
}

export function AccessSheet({
  connection,
  initial,
  save,
  close,
}: {
  connection?: FirewallConnection;
  initial?: FirewallAccess;
  save: (access: FirewallAccess) => void;
  close: () => void;
}) {
  const t = useT();
  const mobile = useIsMobile();
  return (
    <Sheet open={Boolean(connection)} onOpenChange={(open) => !open && close()}>
      <SheetContent
        side={mobile ? "bottom" : "right"}
        closeLabel={t("close")}
        className="fw-sheet gap-0"
      >
        {connection && initial && (
          <Editor
            key={connection.id}
            connection={connection}
            initial={initial}
            save={save}
            close={close}
          />
        )}
      </SheetContent>
    </Sheet>
  );
}
