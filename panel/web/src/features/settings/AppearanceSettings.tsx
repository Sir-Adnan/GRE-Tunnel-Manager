import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Switch } from "@/components/ui/switch";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Choice } from "@/components/shared";
import { HelpTip } from "@/components/help";
import { ThemePicker } from "@/components/ThemePicker";
import { useT } from "@/lib/i18n";
import type { Locale, Preferences } from "@/lib/preferences";

export function AppearanceSettings({
  preferences,
  setPreferences,
}: {
  preferences: Preferences;
  setPreferences: (value: Preferences) => void;
}) {
  const t = useT();
  return (
    <div className="page-stack">
      <Card>
        <CardHeader>
          <CardTitle>{t("appearance")}</CardTitle>
          <CardDescription>{t("appearanceDesc")}</CardDescription>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            <Choice
              id="language"
              label={t("language")}
              value={preferences.locale}
              onChange={(value) =>
                setPreferences({ ...preferences, locale: value as Locale })
              }
              choices={[
                { value: "fa", label: "فارسی" },
                { value: "en", label: "English" },
              ]}
            />
            <Field>
              <FieldLabel>{t("mode")}</FieldLabel>
              <ToggleGroup
                type="single"
                variant="outline"
                value={preferences.mode}
                onValueChange={(value) =>
                  value &&
                  setPreferences({
                    ...preferences,
                    mode: value as Preferences["mode"],
                  })
                }
              >
                {["light", "dark", "system"].map((mode) => (
                  <ToggleGroupItem value={mode} key={mode}>
                    {t(mode)}
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>
            </Field>
            <Field orientation="horizontal">
              <div className="flex items-center gap-1">
                <FieldLabel htmlFor="auto-refresh">
                  {t("autoRefresh")}
                </FieldLabel>
                <HelpTip label={t("autoRefresh")}>
                  {t("autoRefreshHelp")}
                </HelpTip>
              </div>
              <Switch
                id="auto-refresh"
                checked={preferences.refresh}
                onCheckedChange={(value) =>
                  setPreferences({ ...preferences, refresh: value })
                }
              />
            </Field>
          </FieldGroup>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-1">
            {t("style")}
            <HelpTip>
              {t("styleHelp")} {t("exactTheme")}
            </HelpTip>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ThemePicker
            value={preferences.style}
            locale={preferences.locale}
            onChange={(style) => setPreferences({ ...preferences, style })}
          />
        </CardContent>
      </Card>
    </div>
  );
}
