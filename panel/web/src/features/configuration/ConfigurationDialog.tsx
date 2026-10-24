import { useEffect, useState } from "react";
import { Copy, Download, Code2 } from "lucide-react";
import { api } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
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
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { LocaleContext } from "@/lib/i18n";
import { useContext } from "react";

type View = {
  id: string;
  revision: string;
  engine: string;
  editor?: string;
  native_editable: boolean;
  saved_state: string;
  files: { name: string; path: string; text: string; kind: string }[];
};
type Selection = { id: string; revision: string; name?: string };

export function ConfigurationDialog({
  resource,
  onClose,
  run,
}: {
  resource: Selection;
  onClose: () => void;
  run: (r: unknown) => Promise<void>;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const [view, setView] = useState<View>(),
    [error, setError] = useState("");
  const [tab, setTab] = useState("view"),
    [json, setJSON] = useState(""),
    [native, setNative] = useState("");
  const [busy, setBusy] = useState(false),
    [copied, setCopied] = useState(false);
  const [review, setReview] = useState<{
    format: string;
    text: string;
    view: View;
  }>();
  useEffect(() => {
    let live = true;
    api<View>(
      `configuration?id=${encodeURIComponent(resource.id)}&revision=${encodeURIComponent(resource.revision)}`,
    )
      .then((v) => {
        if (live) {
          setView(v);
          setJSON(v.editor || "");
          setNative(v.files[0]?.text || "");
        }
      })
      .catch((e) => {
        if (live) setError(String(e));
      });
    return () => {
      live = false;
    };
  }, [resource.id, resource.revision]);
  const format = tab === "json" ? "json" : "native",
    text = format === "json" ? json : native;
  const displayed =
    tab === "view" ? view?.files.map((f) => f.text).join("\n") || "" : text;
  async function check() {
    setBusy(true);
    setError("");
    try {
      const candidate = await api<View>("configuration/review", {
        id: resource.id,
        revision: resource.revision,
        format,
        text,
      });
      setReview({ format, text, view: candidate });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  function download() {
    const url = URL.createObjectURL(
      new Blob([displayed], { type: "text/plain;charset=utf-8" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download =
      tab === "json"
        ? `${resource.id}.manager.json`
        : view?.files[0]?.name || `${resource.id}.conf`;
    a.click();
    URL.revokeObjectURL(url);
  }
  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent
        closeLabel={t("close")}
        scrollLayout="body"
        className="dialog-shell sm:max-w-4xl"
      >
        <DialogHeader className="shrink-0 pe-6">
          <DialogTitle className="flex flex-wrap items-center gap-2">
            <Code2 className="size-4" />
            {t("configuration")} · <bdi>{resource.name || resource.id}</bdi>
          </DialogTitle>
          <DialogDescription>{t("configDescription")}</DialogDescription>
        </DialogHeader>
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {!view && !error && <Skeleton className="h-64 w-full" />}
        {view && (
          <DialogBody>
            {view.saved_state === "different" && (
              <Alert>
                <AlertDescription>{t("configDriftHelp")}</AlertDescription>
              </Alert>
            )}
            {view.files.some((f) => f.kind === "redacted") && (
              <Alert>
                <AlertDescription>{t("configRedactedHelp")}</AlertDescription>
              </Alert>
            )}
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline">{t(`config_${view.saved_state}`)}</Badge>
              <HelpTip label={t("help")}>{t("configHelp")}</HelpTip>
              <bdi className="min-w-0 break-all text-xs text-muted-foreground">
                {view.files[0]?.path}
              </bdi>
            </div>
            <Tabs
              value={tab}
              dir={locale === "fa" ? "rtl" : "ltr"}
              onValueChange={(v) => {
                setTab(v);
                setReview(undefined);
                setError("");
              }}
            >
              <TabsList className="max-w-full flex-wrap">
                <TabsTrigger value="view">{t("viewConfig")}</TabsTrigger>
                {view.editor && (
                  <TabsTrigger value="json">{t("managedEditor")}</TabsTrigger>
                )}
                {view.native_editable && (
                  <TabsTrigger value="native">{t("nativeEditor")}</TabsTrigger>
                )}
              </TabsList>
              <TabsContent value="view">
                <pre
                  dir="ltr"
                  className="max-h-[48dvh] overflow-auto rounded-lg border bg-background p-4 text-start text-xs leading-6"
                >
                  <code>{displayed}</code>
                </pre>
              </TabsContent>
              {["json", "native"].map((mode) => (
                <TabsContent key={mode} value={mode}>
                  <textarea
                    aria-label={t("configText")}
                    dir="ltr"
                    spellCheck={false}
                    maxLength={65536}
                    disabled={busy}
                    value={mode === "json" ? json : native}
                    onChange={(e) => {
                      if (mode === "json") setJSON(e.target.value);
                      else setNative(e.target.value);
                      setReview(undefined);
                      setCopied(false);
                    }}
                    className="h-[40dvh] min-h-48 w-full resize-y rounded-lg border bg-background p-4 font-mono text-start text-xs leading-6"
                  />
                </TabsContent>
              ))}
            </Tabs>
            {tab !== "view" && (
              <p className="text-xs leading-6 text-muted-foreground">
                {t(tab === "native" ? "nativeEditorHelp" : "managedEditorHelp")}
              </p>
            )}
            {review && (
              <section className="flex flex-col gap-2">
                <h3 className="font-medium">{t("configReviewed")}</h3>
                <pre
                  dir="ltr"
                  className="max-h-48 overflow-auto rounded-lg border bg-background p-3 text-start text-xs leading-6"
                >
                  <code>{review.view.files[0]?.text}</code>
                </pre>
                <p className="text-xs leading-6 text-muted-foreground">
                  {t("configApplyHelp")}
                </p>
              </section>
            )}
          </DialogBody>
        )}
        <DialogFooter className="shrink-0 flex-wrap">
          <Button
            variant="outline"
            disabled={!view || busy}
            onClick={() => {
              void navigator.clipboard
                ?.writeText(displayed)
                .then(() => setCopied(true))
                .catch(() => setCopied(false));
            }}
          >
            <Copy data-icon="inline-start" />
            {t(copied ? "copied" : "copyConfig")}
          </Button>
          <Button variant="outline" disabled={!view || busy} onClick={download}>
            <Download data-icon="inline-start" />
            {t("downloadConfig")}
          </Button>
          {tab !== "view" && (
            <Button
              disabled={busy || !view}
              onClick={() =>
                void (async () => {
                  if (!review) {
                    await check();
                    return;
                  }
                  setBusy(true);
                  setError("");
                  try {
                    await run({
                      action: "configuration-apply",
                      configuration: {
                        id: resource.id,
                        revision: resource.revision,
                        format: review.format,
                        text: review.text,
                      },
                    });
                    onClose();
                  } catch (e) {
                    setError(String(e));
                  } finally {
                    setBusy(false);
                  }
                })()
              }
            >
              {t(busy ? "working" : review ? "save" : "review")}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
