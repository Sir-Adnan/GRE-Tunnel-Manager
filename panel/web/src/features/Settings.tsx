import { useState } from "react";
import { Download, LogOut } from "lucide-react";
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
import { Badge } from "@/components/ui/badge";
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldDescription,
} from "@/components/ui/field";
import { Switch } from "@/components/ui/switch";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Choice, PageTitle } from "@/components/shared";
import { styleGallery } from "@/experience/gallery";
import { registry } from "@/experience/registry.generated";
import { useT } from "@/lib/i18n";
import type { Locale } from "@/lib/i18n";
import type { Inventory } from "@/lib/api";
import { EngineDetails } from "./EngineDetails";

export type Preferences = {
  locale: Locale;
  style: string;
  mode: "light" | "dark" | "system";
  refresh: boolean;
};
export function Settings({
  preferences,
  setPreferences,
  logout,
}: {
  preferences: Preferences;
  setPreferences: (value: Preferences) => void;
  logout: () => void;
}) {
  const t = useT();
  const groups = styleGallery(registry, {
    surface: "admin",
    packId: "tunnel-admin",
    locale: preferences.locale,
  });
  return (
    <div className="page-stack">
      <PageTitle title={t("settings")} description={t("appearanceDesc")} />
      <div className="grid items-start gap-5 lg:grid-cols-2">
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
              <Choice
                id="visual-style"
                label={t("style")}
                value={preferences.style}
                onChange={(value) =>
                  setPreferences({ ...preferences, style: value })
                }
                choices={groups.flatMap((group) =>
                  group.items.map((item) => ({
                    value: item.id,
                    label: item.name,
                  })),
                )}
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
                <div>
                  <FieldLabel htmlFor="auto-refresh">
                    {t("autoRefresh")}
                  </FieldLabel>
                  <FieldDescription>{t("autoRefreshHelp")}</FieldDescription>
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
          <CardFooter>
            <p className="text-xs leading-6 text-muted-foreground">
              {t("exactTheme")}
            </p>
          </CardFooter>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>{t("account")}</CardTitle>
            <CardDescription>{t("passwordHelp")}</CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="code-block" dir="ltr">
              sudo gtm-panel reset-password{`\n`}sudo systemctl restart
              gre-manager-panel
            </pre>
          </CardContent>
          <CardFooter>
            <Button variant="outline" onClick={logout}>
              <LogOut data-icon="inline-start" />
              {t("signOut")}
            </Button>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}
export function Components({
  inventory,
  run,
}: {
  inventory: Inventory;
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const [selected, setSelected] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  async function install() {
    setBusy(true);
    try {
      await run({ action: "install", components: selected });
      setSelected([]);
    } catch {
      /* global feedback */
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="page-stack">
      <PageTitle
        title={t("components")}
        description={t("componentsDesc")}
        action={
          <Button
            variant="outline"
            onClick={() =>
              setSelected(
                inventory.components
                  .filter((c) => !c.installed)
                  .map((c) => c.id),
              )
            }
          >
            {t("selectAll")}
          </Button>
        }
      />
      <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
        {inventory.components.map((component) => (
          <Card key={component.id}>
            <CardHeader>
              <div className="flex items-center justify-between gap-3">
                <CardTitle>
                  <span dir="ltr">
                    {component.id === "haproxy"
                      ? "HAProxy"
                      : component.id === "realm"
                        ? "Realm"
                        : component.id}
                  </span>
                </CardTitle>
                <Badge variant={component.installed ? "secondary" : "outline"}>
                  {t(component.installed ? "installed" : "notInstalled")}
                </Badge>
              </div>
              <CardDescription>
                {component.id === "realm"
                  ? "TCP / UDP"
                  : component.id === "haproxy"
                    ? "TCP / health checks / failover"
                    : component.id === "frp"
                      ? "TCP / WS / WSS / QUIC"
                      : component.id === "rathole"
                        ? "Noise NK / TCP / UDP"
                        : "Kernel / TCP / UDP"}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <EngineDetails
                component={component}
                profile={inventory.engine_profiles?.find(
                  (profile) => profile.id === component.id,
                )}
              />
            </CardContent>
            <CardFooter>
              <Field orientation="horizontal">
                <Checkbox
                  id={`install-${component.id}`}
                  disabled={component.installed || busy}
                  checked={selected.includes(component.id)}
                  onCheckedChange={(value) =>
                    setSelected(
                      value
                        ? [...selected, component.id]
                        : selected.filter((id) => id !== component.id),
                    )
                  }
                />
                <FieldLabel htmlFor={`install-${component.id}`}>
                  {t(component.installed ? "installed" : "installSelected")}
                </FieldLabel>
              </Field>
            </CardFooter>
          </Card>
        ))}
      </div>
      <div>
        <Button disabled={selected.length === 0 || busy} onClick={install}>
          <Download data-icon="inline-start" />
          {t(busy ? "working" : "installSelected")}
          {selected.length > 0 && ` (${selected.length})`}
        </Button>
      </div>
    </div>
  );
}
