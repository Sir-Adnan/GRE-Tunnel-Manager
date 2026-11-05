import { useEffect, useState } from "react";
import { BellRing, Loader2, Send, Webhook } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { HelpTip } from "@/components/help";
import { useT } from "@/lib/i18n";
import { useNotifications } from "./hooks";
import type { NotifySettingsInput, NotifyView } from "./types";

type Draft = {
  kinds: string[];
  language: "en" | "fa";
  webhook: boolean;
  url: string;
  secret: string;
  telegram: boolean;
  token: string;
  chat: string;
  api: string;
};

function draftOf(v: NotifyView): Draft {
  const s = v.settings;
  return {
    kinds: s.kinds,
    language: s.language,
    webhook: s.webhook.enabled,
    url: "",
    secret: "",
    telegram: s.telegram.enabled,
    token: "",
    chat: s.telegram.chat ?? "",
    api: s.telegram.api ?? "",
  };
}

/** Channels for notifications: webhook and Telegram, and the kinds they get. */
export function NotificationSettings({
  run,
}: {
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const { value, error, reload } = useNotifications();
  const [draft, setDraft] = useState<Draft>();
  const [busy, setBusy] = useState(false);
  const revision = value?.revision;
  useEffect(() => {
    if (value) setDraft(draftOf(value));
    // Reset the form only when the stored settings change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revision]);
  if (!value || !draft)
    return error ? (
      <Alert variant="destructive">
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    ) : null;
  const s = value.settings;
  const set = (patch: Partial<Draft>) => setDraft({ ...draft, ...patch });
  async function act(request: unknown) {
    setBusy(true);
    try {
      await run(request);
    } catch {
      // The operation dialog shows the error.
    } finally {
      setBusy(false);
      await reload();
    }
  }
  const input = (forget?: "webhook" | "telegram"): NotifySettingsInput => ({
    kinds: draft.kinds,
    language: draft.language,
    webhook: {
      enabled: forget === "webhook" ? false : draft.webhook,
      ...(draft.url && { url: draft.url }),
      ...(draft.secret && { secret: draft.secret }),
      ...(forget === "webhook" && { forget: true }),
    },
    telegram: {
      enabled: forget === "telegram" ? false : draft.telegram,
      ...(draft.token && { token: draft.token }),
      chat: draft.chat,
      api: draft.api,
      ...(forget === "telegram" && { forget: true }),
    },
  });
  const save = (forget?: "webhook" | "telegram") =>
    act({
      action: "notifications-configure",
      notify: { settings: input(forget), revision: value.revision },
    });
  const anyOn = s.webhook.enabled || s.telegram.enabled;
  return (
    <Card id="notifications">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <BellRing className="size-4 text-muted-foreground" aria-hidden />
          {t("ntfChannels")}
        </CardTitle>
        <CardDescription>{t("ntfChannelsHelp")}</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="flex flex-col gap-6"
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <FieldSet>
            <div className="flex items-center justify-between gap-3">
              <FieldLegend className="flex items-center gap-2">
                <Webhook className="size-4" aria-hidden />
                {t("ntfWebhook")}
              </FieldLegend>
              <Switch
                aria-label={t("ntfWebhook")}
                checked={draft.webhook}
                onCheckedChange={(webhook) => set({ webhook })}
                disabled={busy}
              />
            </div>
            <FieldDescription>{t("ntfWebhookHelp")}</FieldDescription>
            <FieldGroup columns>
              <Field>
                <FieldLabel htmlFor="ntf-url">{t("ntfWebhookUrl")}</FieldLabel>
                <Input
                  id="ntf-url"
                  dir="ltr"
                  type="url"
                  inputMode="url"
                  autoComplete="off"
                  placeholder={s.webhook.url_set ? t("ntfSavedAt").replace("{host}", s.webhook.host ?? "") : "https://hooks.example.com/…"}
                  value={draft.url}
                  onChange={(e) => set({ url: e.target.value })}
                  disabled={busy}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="ntf-secret" className="flex items-center gap-2">
                  {t("ntfWebhookSecret")}
                  <HelpTip label={t("ntfWebhookSecret")}>{t("ntfWebhookSecretHelp")}</HelpTip>
                </FieldLabel>
                <Input
                  id="ntf-secret"
                  dir="ltr"
                  type="password"
                  autoComplete="new-password"
                  placeholder={s.webhook.secret_set ? t("ntfSaved") : t("optional")}
                  value={draft.secret}
                  onChange={(e) => set({ secret: e.target.value })}
                  disabled={busy}
                />
              </Field>
            </FieldGroup>
          </FieldSet>
          <FieldSet>
            <div className="flex items-center justify-between gap-3">
              <FieldLegend className="flex items-center gap-2">
                <Send className="size-4" aria-hidden />
                {t("ntfTelegram")}
              </FieldLegend>
              <Switch
                aria-label={t("ntfTelegram")}
                checked={draft.telegram}
                onCheckedChange={(telegram) => set({ telegram })}
                disabled={busy}
              />
            </div>
            <FieldDescription>{t("ntfTelegramHelp")}</FieldDescription>
            <FieldGroup columns>
              <Field>
                <FieldLabel htmlFor="ntf-token">{t("ntfBotToken")}</FieldLabel>
                <Input
                  id="ntf-token"
                  dir="ltr"
                  type="password"
                  autoComplete="off"
                  placeholder={s.telegram.token_set ? t("ntfSaved") : "123456:ABC…"}
                  value={draft.token}
                  onChange={(e) => set({ token: e.target.value })}
                  disabled={busy}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="ntf-chat">{t("ntfChat")}</FieldLabel>
                <Input
                  id="ntf-chat"
                  dir="ltr"
                  autoComplete="off"
                  placeholder="-1001234567890 · @channel"
                  value={draft.chat}
                  onChange={(e) => set({ chat: e.target.value })}
                  disabled={busy}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="ntf-api" className="flex items-center gap-2">
                  {t("ntfApi")}
                  <HelpTip label={t("ntfApi")}>{t("ntfApiHelp")}</HelpTip>
                </FieldLabel>
                <Input
                  id="ntf-api"
                  dir="ltr"
                  type="url"
                  autoComplete="off"
                  placeholder="https://api.telegram.org"
                  value={draft.api}
                  onChange={(e) => set({ api: e.target.value })}
                  disabled={busy}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="ntf-language">{t("ntfLanguage")}</FieldLabel>
                <NativeSelect
                  id="ntf-language"
                  value={draft.language}
                  onChange={(e) => set({ language: e.target.value as "en" | "fa" })}
                  disabled={busy}
                >
                  <NativeSelectOption value="en">English</NativeSelectOption>
                  <NativeSelectOption value="fa">فارسی</NativeSelectOption>
                </NativeSelect>
              </Field>
            </FieldGroup>
          </FieldSet>
          <FieldSet>
            <FieldLegend>{t("ntfKinds")}</FieldLegend>
            <FieldDescription>{t("ntfKindsHelp")}</FieldDescription>
            <div className="ntf-kinds">
              {value.kinds.map((kind) => (
                <Field key={kind} orientation="horizontal">
                  <Checkbox
                    id={`ntf-kind-${kind}`}
                    checked={draft.kinds.includes(kind)}
                    disabled={busy}
                    onCheckedChange={(on) =>
                      set({
                        kinds: on
                          ? [...draft.kinds, kind]
                          : draft.kinds.filter((k) => k !== kind),
                      })
                    }
                  />
                  <FieldContent>
                    <FieldLabel htmlFor={`ntf-kind-${kind}`} className="font-normal">
                      {t(`ntfKind_${kind}`)}
                    </FieldLabel>
                  </FieldContent>
                </Field>
              ))}
            </div>
          </FieldSet>
          <div className="flex flex-wrap items-center justify-end gap-2 border-t pt-4">
            {s.webhook.url_set && (
              <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => void save("webhook")}>
                {t("ntfForgetWebhook")}
              </Button>
            )}
            {s.telegram.token_set && (
              <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => void save("telegram")}>
                {t("ntfForgetTelegram")}
              </Button>
            )}
            <Button
              type="button"
              variant="outline"
              disabled={busy || !anyOn}
              title={anyOn ? undefined : t("ntfTestNeedsChannel")}
              onClick={() => void act({ action: "notifications-test" })}
            >
              <Send data-icon="inline-start" />
              {t("ntfTest")}
            </Button>
            <Button type="submit" disabled={busy}>
              {busy && <Loader2 className="animate-spin" data-icon="inline-start" />}
              {t("ntfSave")}
            </Button>
          </div>
        </form>
      </CardContent>
      <CardFooter>
        <p className="text-xs leading-6 text-muted-foreground">{t("ntfPrivacy")}</p>
      </CardFooter>
    </Card>
  );
}
