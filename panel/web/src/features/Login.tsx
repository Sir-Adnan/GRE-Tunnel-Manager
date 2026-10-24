import { useState } from "react";
import {
  ArrowRight,
  Globe2,
  Loader2,
  Network,
  Server,
  ShieldAlert,
  ShieldCheck,
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
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { FieldGroup } from "@/components/ui/field";
import { Logo, TextField } from "@/components/shared";
import { api } from "@/lib/api";
import type { Session } from "@/lib/api";
import type { Preferences } from "@/features/Settings";
export function Login({
  t,
  setSession,
  demo,
  preferences,
  setPreferences,
}: {
  t: (key: string) => string;
  setSession: (value: Session) => void;
  demo: boolean;
  preferences: Preferences;
  setPreferences: (value: Preferences) => void;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      setSession(await api<Session>("login", { username, password }));
    } catch (error) {
      setError(String(error instanceof Error ? error.message : error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="login-shell">
      <div className="login-top">
        <Logo />
        <Button
          variant="ghost"
          onClick={() =>
            setPreferences({
              ...preferences,
              locale: preferences.locale === "fa" ? "en" : "fa",
            })
          }
        >
          <Globe2 data-icon="inline-start" />
          {preferences.locale === "fa" ? "English" : "فارسی"}
        </Button>
      </div>
      <div className="login-center">
        <div className="login-intro">
          <Badge variant="outline">GRE · FORWARDING · REVERSE</Badge>
          <h1>{t("headline")}</h1>
          <p>{t("quietDesc")}</p>
          <div className="connection-art" aria-hidden>
            <span>
              <Server />
            </span>
            <i />
            <span className="connection-art-center">
              <Network />
            </span>
            <i />
            <span>
              <Server />
            </span>
          </div>
        </div>
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>{t("loginTitle")}</CardTitle>
            <CardDescription>{t("loginDesc")}</CardDescription>
          </CardHeader>
          <CardContent>
            <form id="login" onSubmit={submit}>
              <FieldGroup>
                {error && (
                  <Alert>
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                )}
                {!demo && location.protocol !== "https:" && (
                  <Alert>
                    <ShieldAlert />
                    <AlertDescription>{t("httpHelp")}</AlertDescription>
                  </Alert>
                )}
                <TextField
                  id="username"
                  label={t("username")}
                  autoComplete="username"
                  dir="ltr"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  required
                  maxLength={40}
                />
                <TextField
                  id="password"
                  label={t("password")}
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                  maxLength={72}
                />
                {demo && (
                  <p className="text-xs text-muted-foreground">
                    {t("demoLogin")}
                  </p>
                )}
              </FieldGroup>
            </form>
          </CardContent>
          <CardFooter className="flex flex-col gap-5">
            <Button
              className="w-full"
              size="lg"
              type="submit"
              form="login"
              disabled={busy}
            >
              {busy ? (
                <Loader2 data-icon="inline-start" className="animate-spin" />
              ) : (
                <ArrowRight
                  data-icon="inline-start"
                  className="rtl:rotate-180"
                />
              )}
              {t("signIn")}
            </Button>
            <span className="flex items-center gap-2 text-xs text-muted-foreground">
              {location.protocol === "https:" ? (
                <ShieldCheck className="size-3.5" />
              ) : (
                <ShieldAlert className="size-3.5" />
              )}
              {demo
                ? "LOCAL DEMO"
                : t(location.protocol === "https:" ? "secure" : "httpAccess")}
            </span>
          </CardFooter>
        </Card>
      </div>
      <footer className="login-bottom">
        TUNNEL MANAGER <span>v1.3.2</span>
      </footer>
    </div>
  );
}
