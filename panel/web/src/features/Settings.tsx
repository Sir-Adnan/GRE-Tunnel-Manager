import { useState } from "react";
import { usePanelRoute } from "@/lib/use-panel-route";
import {
  Download,
  LogOut,
  ShieldCheck,
  Palette,
  Bell,
  Activity,
} from "lucide-react";
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
import { Field, FieldLabel } from "@/components/ui/field";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageTitle } from "@/components/shared";
import { useT } from "@/lib/i18n";
import type { Preferences } from "@/lib/preferences";
import type { Inventory } from "@/lib/api";
import { EngineDetails } from "./EngineDetails";
import { EngineUpdates } from "./engines/EngineUpdates";
import { NotificationSettings } from "./notifications/NotificationSettings";
import { MetricsExport } from "./settings/MetricsExport";
import { AccessSecurity } from "./settings/AccessSecurity";
import { AppearanceSettings } from "./settings/AppearanceSettings";
import { settingsTab } from "./settings/navigation";

export function Settings({
  run,
  preferences,
  setPreferences,
  logout,
}: {
  run: (request: unknown) => Promise<void>;
  preferences: Preferences;
  setPreferences: (value: Preferences) => void;
  logout: () => void;
}) {
  const t = useT();
  const { params, updateParams } = usePanelRoute();
  const tab = settingsTab(params);
  const sections = [
    { id: "security", title: "settingsSecurity", icon: ShieldCheck },
    { id: "appearance", title: "appearance", icon: Palette },
    { id: "notifications", title: "settingsNotifications", icon: Bell },
    { id: "metrics", title: "settingsMetrics", icon: Activity },
  ];
  return (
    <div className="page-stack">
      <PageTitle title={t("settings")} description={t("settingsIntro")} />
      <Tabs
        value={tab}
        onValueChange={(tab) => updateParams({ tab, section: "" }, true)}
        className="settings-workspace"
        dir={preferences.locale === "fa" ? "rtl" : "ltr"}
      >
        <TabsList
          className="settings-tabs grid h-auto w-full grid-cols-2 group-data-[orientation=horizontal]/tabs:h-auto sm:flex sm:w-fit"
          aria-label={t("settings")}
        >
          {sections.map(({ id, title, icon: Icon }) => (
            <TabsTrigger
              key={id}
              value={id}
              className="h-auto min-h-11 whitespace-normal px-3 py-2"
            >
              <Icon />
              <span>{t(title)}</span>
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="security" forceMount className="settings-panel">
          <AccessSecurity />
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
        </TabsContent>
        <TabsContent value="appearance" forceMount className="settings-panel">
          <AppearanceSettings
            preferences={preferences}
            setPreferences={setPreferences}
          />
        </TabsContent>
        <TabsContent
          value="notifications"
          forceMount
          className="settings-panel"
        >
          <NotificationSettings run={run} />
        </TabsContent>
        <TabsContent value="metrics" forceMount className="settings-panel">
          <MetricsExport />
        </TabsContent>
      </Tabs>
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
      <EngineUpdates run={run} />
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
