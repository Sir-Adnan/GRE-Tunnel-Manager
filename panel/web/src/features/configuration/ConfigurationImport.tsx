import { useContext, useState } from "react";
import { FileUp, Check, ArrowLeft } from "lucide-react";
import { api, endpoint, type Connection } from "@/lib/api";
import { LocaleContext, useT } from "@/lib/i18n";
import { useDiscardChanges } from "@/lib/use-discard-changes";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Choice } from "@/components/shared";
import { HelpTip } from "@/components/help";
import {
  Dialog,
  DialogContent,
  DialogBody,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";

type Review = {
  review: string;
  connections: Connection[];
  warnings: string[];
  files: { name: string; text: string }[];
};
export function ConfigurationImport({
  engine,
  onClose,
  run,
}: {
  engine: string;
  onClose: () => void;
  run: (r: unknown) => Promise<void>;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const [method, setMethod] = useState(engine),
    [format, setFormat] = useState(
      ["haproxy", "realm"].includes(engine) ? engine : "json",
    );
  const [text, setText] = useState(""),
    [activate, setActivate] = useState(false),
    [review, setReview] = useState<Review>(),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const { requestClose, confirmation } = useDiscardChanges(
    text !== "" && !busy,
    onClose,
  );
  function invalidate() {
    setReview(undefined);
    setError("");
  }
  async function check() {
    setBusy(true);
    setError("");
    try {
      setReview(
        await api<Review>("configuration/import/review", {
          engine: method,
          format,
          text,
          activate,
        }),
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function apply() {
    if (!review) return;
    setBusy(true);
    setError("");
    try {
      await run({
        action: "configuration-import-apply",
        import: {
          engine: method,
          format,
          text,
          activate,
          review: review.review,
        },
      });
      onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Dialog open onOpenChange={(v) => !v && !busy && requestClose()}>
        <DialogContent
          scrollLayout="body"
          closeLabel={t("close")}
          className="dialog-shell sm:max-w-4xl"
        >
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileUp className="size-5" />
              {t("importConfiguration")}
            </DialogTitle>
            <DialogDescription>
              {t("importConfigurationHelp")}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            {error && (
              <Alert variant="destructive" role="alert">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            {!review ? (
              <FieldGroup>
                <FieldGroup columns>
                  <Choice
                    id="import-engine"
                    label={t("method")}
                    value={method}
                    choices={["haproxy", "realm", "iptables", "nftables"].map(
                      (id) => ({
                        value: id,
                        label:
                          id === "haproxy"
                            ? "HAProxy"
                            : id === "realm"
                              ? "Realm"
                              : id,
                      }),
                    )}
                    onChange={(v) => {
                      setMethod(v);
                      setFormat(["haproxy", "realm"].includes(v) ? v : "json");
                      invalidate();
                    }}
                  />
                  <Choice
                    id="import-format"
                    label={t("configFormat")}
                    value={format}
                    choices={[
                      ...(["haproxy", "realm"].includes(method)
                        ? [{ value: method, label: t("nativeEditor") }]
                        : []),
                      { value: "json", label: t("managedEditor") },
                    ]}
                    onChange={(v) => {
                      setFormat(v);
                      invalidate();
                    }}
                  />
                </FieldGroup>
                <Field>
                  <div className="flex items-center gap-2">
                    <FieldLabel htmlFor="import-file">
                      {t("configFile")}
                    </FieldLabel>
                    <HelpTip>{t("importScopeHelp")}</HelpTip>
                  </div>
                  <Input
                    id="import-file"
                    type="file"
                    accept=".cfg,.conf,.toml,.json,.txt"
                    disabled={busy}
                    onChange={async (e) => {
                      const f = e.target.files?.[0];
                      if (!f) return;
                      if (f.size > 65536) {
                        setError(t("configFileTooLarge"));
                        return;
                      }
                      setText(await f.text());
                      invalidate();
                    }}
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="import-text">
                    {t("configText")}
                  </FieldLabel>
                  <textarea
                    id="import-text"
                    dir="ltr"
                    spellCheck={false}
                    maxLength={65536}
                    className="config-editor"
                    value={text}
                    onChange={(e) => {
                      setText(e.target.value);
                      invalidate();
                    }}
                    placeholder={
                      format === "json"
                        ? '[ { "engine": "' + method + '", ... } ]'
                        : method === "haproxy"
                          ? "global\n\ndefaults\n    mode tcp\n\nfrontend ..."
                          : "[network]\n\n[[endpoints]]\nlisten = ...\nremote = ..."
                    }
                  />
                </Field>
                <Field orientation="horizontal">
                  <FieldLabel htmlFor="import-activate">
                    {t("startAfterSave")}
                  </FieldLabel>
                  <HelpTip>{t("importActivateHelp")}</HelpTip>
                  <Switch
                    id="import-activate"
                    checked={activate}
                    onCheckedChange={(v) => {
                      setActivate(v);
                      invalidate();
                    }}
                  />
                </Field>
              </FieldGroup>
            ) : (
              <div className="flex flex-col gap-4">
                <Alert>
                  <AlertDescription>
                    {t(activate ? "importStarts" : "importPaused")}
                  </AlertDescription>
                </Alert>
                <div className="divide-y rounded-lg border">
                  {review.connections.map((c, i) => (
                    <div
                      key={i}
                      className="grid min-w-0 gap-2 p-3 sm:grid-cols-[minmax(0,1fr)_6rem_minmax(0,1fr)]"
                    >
                      <bdi className="break-words font-medium">{c.name}</bdi>
                      <bdi className="font-mono text-sm">{c.ports}</bdi>
                      <div className="flex min-w-0 flex-col gap-1">
                        {c.targets.map((a, n) => (
                          <bdi
                            key={n}
                            dir="ltr"
                            className="break-all font-mono text-xs"
                          >
                            {endpoint(a.ip, a.port)}
                          </bdi>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
                {review.warnings.length > 0 && (
                  <details className="rounded-lg border p-3">
                    <summary className="cursor-pointer text-sm">
                      {t("importReplacedSettings")} ({review.warnings.length})
                    </summary>
                    <ul className="mt-3 flex flex-col gap-2 text-xs">
                      {review.warnings.map((w, i) => (
                        <li
                          key={i}
                          dir={
                            w === "managed-services-per-listener" &&
                            locale === "fa"
                              ? "rtl"
                              : "ltr"
                          }
                          className="[overflow-wrap:anywhere]"
                        >
                          {w === "managed-services-per-listener"
                            ? t("importSeparateServices")
                            : w.replace(
                                /^Manager process settings replace: /,
                                "",
                              )}
                        </li>
                      ))}
                    </ul>
                  </details>
                )}
                <details className="rounded-lg border p-3">
                  <summary className="cursor-pointer text-sm">
                    {t("previewAll")}
                  </summary>
                  {review.files.map((f, i) => (
                    <pre key={i} className="code-block mt-3" dir="ltr">
                      {f.text}
                    </pre>
                  ))}
                </details>
              </div>
            )}
          </DialogBody>
          <DialogFooter>
            {review && (
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => setReview(undefined)}
              >
                <ArrowLeft
                  data-icon="inline-start"
                  className={locale === "fa" ? "rotate-180" : undefined}
                />
                {t("edit")}
              </Button>
            )}
            <Button variant="outline" disabled={busy} onClick={requestClose}>
              {t("cancel")}
            </Button>
            <Button
              disabled={busy || !text.trim()}
              onClick={review ? apply : check}
            >
              <Check data-icon="inline-start" />
              {t(busy ? "working" : review ? "importSave" : "review")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {confirmation}
    </>
  );
}
