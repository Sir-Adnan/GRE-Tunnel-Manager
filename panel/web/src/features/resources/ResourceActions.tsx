import { useContext, useState } from "react";
import {
  Code2,
  FileText,
  MoreHorizontal,
  Pencil,
  Play,
  RotateCw,
  Square,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { LocaleContext, useT } from "@/lib/i18n";
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
  const t = useT(),
    locale = useContext(LocaleContext);
  const [busy, setBusy] = useState(false);
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
      <DropdownMenu dir={locale === "fa" ? "rtl" : "ltr"}>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            disabled={busy}
            aria-label={`${t("moreActions")} ${resource.name}`}
          >
            <MoreHorizontal />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="min-w-48">
          <DropdownMenuGroup>
            <DropdownMenuItem onSelect={onRename}>
              <Pencil />
              {t("renameDisplay")}
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => void service("enable")}>
              <Play />
              {t("startAtBoot")}
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => void service("stop")}>
              <Square />
              {t("stop")}
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => void service("restart")}>
              <RotateCw />
              {t("restart")}
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => void service("logs")}>
              <FileText />
              {t("logs")}
            </DropdownMenuItem>
          </DropdownMenuGroup>
          <DropdownMenuSeparator />
          <DropdownMenuGroup>
            <DropdownMenuItem variant="destructive" onSelect={onDelete}>
              <Trash2 />
              {t("delete")}
            </DropdownMenuItem>
          </DropdownMenuGroup>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}
