import { useState } from "react";
import {
  Code2,
  FileText,
  Pencil,
  Play,
  RotateCw,
  Square,
  Stethoscope,
  Trash2,
} from "lucide-react";
import { DiagnoseDialog } from "@/features/diagnose/DiagnoseDialog";
import { Button } from "@/components/ui/button";
import { ActionMenu } from "@/components/ActionMenu";
import { useT } from "@/lib/i18n";
import type { Resource } from "@/lib/api";

export function ResourceActions({
  resource,
  onConfig,
  onRename,
  onDelete,
  run,
}: {
  resource: Resource;
  onConfig: () => void;
  onRename: () => void;
  onDelete: () => void;
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const [busy, setBusy] = useState(false);
  const [diagnosing, setDiagnosing] = useState(false);
  const diagnosable = /^gre-tun-[0-9]{1,3}$/.test(resource.id);
  async function service(action: string) {
    setBusy(true);
    try {
      await run({
        action: action === "logs" ? "logs" : "service",
        service: resource.id,
        verb: action,
      });
    } catch {
      /* The operation controller shows the server error. */
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="flex w-full items-center justify-between gap-2">
      <Button variant="ghost" size="sm" disabled={busy} onClick={onConfig}>
        <Code2 data-icon="inline-start" />
        {t("viewConfig")}
      </Button>
      <ActionMenu
        label={`${t("moreActions")} ${resource.name}`}
        title={resource.name}
        disabled={busy}
        groups={[
          [
            {
              id: "rename",
              label: t("renameDisplay"),
              icon: <Pencil />,
              onSelect: onRename,
            },
            {
              id: "enable",
              label: t("startAtBoot"),
              icon: <Play />,
              onSelect: () => void service("enable"),
            },
            {
              id: "stop",
              label: t("stop"),
              icon: <Square />,
              onSelect: () => void service("stop"),
            },
            {
              id: "restart",
              label: t("restart"),
              icon: <RotateCw />,
              onSelect: () => void service("restart"),
            },
            {
              id: "logs",
              label: t("logs"),
              icon: <FileText />,
              onSelect: () => void service("logs"),
            },
            ...(diagnosable
              ? [
                  {
                    id: "diagnose",
                    label: t("diagOpen"),
                    icon: <Stethoscope />,
                    onSelect: () => setDiagnosing(true),
                  },
                ]
              : []),
          ],
          [
            {
              id: "delete",
              label: t("delete"),
              icon: <Trash2 />,
              onSelect: onDelete,
              destructive: true,
            },
          ],
        ]}
      />
      <DiagnoseDialog
        key={String(diagnosing)}
        owner={diagnosing ? resource.id : undefined}
        name={resource.name}
        onClose={() => setDiagnosing(false)}
      />
    </div>
  );
}
