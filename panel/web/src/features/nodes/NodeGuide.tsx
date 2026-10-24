import { useState } from "react";
import { Button } from "@/components/ui/button";
import { FieldGroup } from "@/components/ui/field";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { TextField } from "@/components/shared";
import { CommandBlock } from "@/components/CommandBlock";
import { useT } from "@/lib/i18n";
import { agentCommand, controllerCommand } from "./setup";

export function NodeGuide({
  enabled,
  refresh,
}: {
  enabled: boolean;
  refresh: () => void;
}) {
  const t = useT();
  const [host, setHost] = useState(window.location.hostname);
  const command = controllerCommand(host);
  return (
    <div className="flex flex-col gap-6">
      <section className="flex flex-col gap-3">
        <h3 className="font-semibold">{t("nodeStepController")}</h3>
        {enabled ? (
          <p className="text-sm text-muted-foreground">{t("localReady")}</p>
        ) : (
          <>
            <FieldGroup>
              <TextField
                id="controller-address"
                label={t("controllerAddress")}
                dir="ltr"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                maxLength={253}
              />
            </FieldGroup>
            {command && <CommandBlock text={command} />}
            <p className="text-sm leading-7 text-muted-foreground">
              {t("controllerSetupStep")}
            </p>
            <Button variant="outline" className="self-start" onClick={refresh}>
              {t("refresh")}
            </Button>
          </>
        )}
        <Alert>
          <AlertDescription>{t("controllerHTTPNote")}</AlertDescription>
        </Alert>
      </section>
      <section className="flex flex-col gap-2">
        <h3 className="font-semibold">{t("nodeStepInvite")}</h3>
        <p className="text-sm leading-7 text-muted-foreground">
          {t("nodeStepInviteHelp")}
        </p>
      </section>
      <section className="flex flex-col gap-3">
        <h3 className="font-semibold">{t("nodeStepAgent")}</h3>
        <p className="text-sm leading-7 text-muted-foreground">
          {t("nodeStepAgentHelp")}
        </p>
        <CommandBlock text={agentCommand} />
      </section>
      <details className="rounded-lg border p-3">
        <summary className="cursor-pointer font-medium">
          {t("advanced")}
        </summary>
        <div className="mt-3 flex flex-col gap-3 text-sm leading-7 text-muted-foreground">
          <p>{t("nodeCapabilitiesHelp")}</p>
          <p>{t("localGuide")}</p>
          <p>{t("nodeRecoveryGuide")}</p>
        </div>
      </details>
    </div>
  );
}
