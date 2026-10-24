import { useContext, useState } from "react";
import { ArrowRight, Check, RadioTower } from "lucide-react";
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
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { useDiscardChanges } from "@/lib/use-discard-changes";
import { Address } from "@/components/shared";
import { LocaleContext, useT } from "@/lib/i18n";
import { engineName } from "@/lib/format";
import type { Connection, Inventory } from "@/lib/api";
import { useConnectionDraft } from "./useConnectionDraft";
import { ConnectionBasics } from "./ConnectionBasics";
import { ConnectionAdvanced } from "./ConnectionAdvanced";
import { ConnectionReview } from "./ConnectionReview";

type Props = {
  inventory: Inventory;
  engine: string;
  engines?: string[];
  original?: Connection;
  onClose: () => void;
  onSubmit: (request: unknown) => Promise<void>;
};

export function ConnectionForm({
  inventory,
  engine,
  engines,
  original,
  onClose,
  onSubmit,
}: Props) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const draft = useConnectionDraft({ inventory, engine, original });
  const { value, installed } = draft;
  const [section, setSection] = useState("connection");
  const [review, setReview] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const { requestClose, confirmation } = useDiscardChanges(
    draft.dirty && !busy,
    onClose,
  );
  async function submit() {
    setBusy(true);
    setError("");
    try {
      await onSubmit({
        action: original ? "update" : "create",
        connection: value,
        ...(original
          ? { selected: [{ id: original.id, revision: original.revision }] }
          : {}),
      });
      onClose();
    } catch (error) {
      setError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Dialog open onOpenChange={(open) => !open && !busy && requestClose()}>
        <DialogContent
          closeLabel={t("close")}
          scrollLayout="body"
          className="dialog-shell connection-editor sm:max-w-4xl"
          onEscapeKeyDown={(event) => busy && event.preventDefault()}
        >
          <DialogHeader>
            <div className="flex items-center gap-3">
              <span className="engine-icon">
                <RadioTower className="size-4" />
              </span>
              <div className="min-w-0">
                <DialogTitle>
                  {t(original ? "edit" : "newConnection")}
                </DialogTitle>
                <DialogDescription>
                  <bdi>{engineName(value.engine)}</bdi> ·{" "}
                  {inventory.host.hostname}
                </DialogDescription>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-1">
              {[
                ...new Set(
                  [
                    inventory.host.public_ip,
                    ...inventory.host.addresses,
                  ].filter((ip): ip is string => Boolean(ip)),
                ),
              ]
                .slice(0, 2)
                .map((ip) => (
                  <Address key={ip}>{ip}</Address>
                ))}
            </div>
          </DialogHeader>
          <DialogBody key={review ? "review" : "form"}>
            {error && (
              <Alert variant="destructive" role="alert">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            {!installed && (
              <Alert>
                <AlertDescription>{t("needsInstall")}</AlertDescription>
              </Alert>
            )}
            {review ? (
              <ConnectionReview value={value} />
            ) : (
              <form
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
                  const invalid =
                    event.currentTarget.querySelector<HTMLInputElement>(
                      "input:invalid,select:invalid,textarea:invalid",
                    );
                  if (invalid) {
                    invalid.setAttribute("aria-invalid", "true");
                    invalid
                      .closest("[data-slot=field]")
                      ?.setAttribute("data-invalid", "true");
                    const advanced = invalid.closest("[data-advanced-section]");
                    setSection(advanced ? "advanced" : "connection");
                    if (advanced)
                      (
                        advanced
                          .closest("[data-slot=tabs]")
                          ?.querySelector(
                            `[data-slot=tabs-trigger][data-advanced-tab="${advanced.getAttribute("data-advanced-section")}"]`,
                          ) as HTMLButtonElement | null
                      )?.click();
                    setError(t("checkFields"));
                    requestAnimationFrame(() => {
                      invalid.focus();
                      invalid.reportValidity();
                    });
                    return;
                  }
                  setError("");
                  setReview(true);
                }}
              >
                <Tabs
                  dir={locale === "fa" ? "rtl" : "ltr"}
                  value={section}
                  onValueChange={setSection}
                  className="gap-5"
                >
                  <TabsList variant="line" aria-label={t("connectionSections")}>
                    <TabsTrigger value="connection">
                      {t("connectionSetup")}
                    </TabsTrigger>
                    <TabsTrigger value="advanced">{t("advanced")}</TabsTrigger>
                  </TabsList>
                  <TabsContent
                    forceMount
                    value="connection"
                    className="data-[state=inactive]:hidden"
                  >
                    <ConnectionBasics
                      draft={draft}
                      inventory={inventory}
                      engines={engines}
                      editing={Boolean(original)}
                    />
                  </TabsContent>
                  <TabsContent
                    forceMount
                    value="advanced"
                    className="data-[state=inactive]:hidden"
                  >
                    <ConnectionAdvanced key={value.engine} draft={draft} />
                  </TabsContent>
                </Tabs>
              </form>
            )}
          </DialogBody>
          <DialogFooter layout="summary" className="connection-editor-footer">
            <div className="min-w-0 flex-1 text-xs text-muted-foreground">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline">{value.protocol.toUpperCase()}</Badge>
                <bdi className="truncate" dir="ltr">
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
                onClick={() => (review ? setReview(false) : requestClose())}
              >
                {t(review ? "back" : "cancel")}
              </Button>
              {review ? (
                <Button disabled={busy || !installed} onClick={submit}>
                  <Check data-icon="inline-start" />
                  {t(busy ? "working" : "save")}
                </Button>
              ) : (
                <Button
                  type="submit"
                  form="connection-form"
                  disabled={!installed}
                >
                  {t("review")}
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
