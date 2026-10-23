import { useState } from "react";
import { ChevronDown, Server } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Popover,
  PopoverTrigger,
  PopoverContent,
} from "@/components/ui/popover";
import {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
} from "@/components/ui/tooltip";
import { HelpTip } from "@/components/help";
import { endpoint } from "@/lib/api";
import type { Connection } from "@/lib/api";
import { useT } from "@/lib/i18n";

export function Destinations({ connection }: { connection: Connection }) {
  const t = useT(),
    [open, setOpen] = useState(false);
  const [tooltipOpen, setTooltipOpen] = useState(false);
  const first = connection.targets[0];
  if (!first) return <span>—</span>;
  if (connection.targets.length === 1)
    return (
      <span className="inline-flex max-w-full">
        <bdi
          dir="ltr"
          className="min-w-0 break-all whitespace-normal font-mono text-xs"
        >
          {endpoint(first.ip, first.port)}
        </bdi>
      </span>
    );
  const list = (limit: number) => (
    <ul
      className="flex max-h-64 flex-col gap-3 overflow-y-auto"
      aria-label={t("destinations")}
    >
      {connection.targets.slice(0, limit).map((target, i) => (
        <li
          key={i}
          className="flex flex-wrap items-center justify-between gap-3"
        >
          <span className="inline-flex min-w-0 items-center gap-2">
            <Server className="size-3.5 shrink-0 text-muted-foreground" />
            <bdi
              dir="ltr"
              className="max-w-full break-all whitespace-normal font-mono text-xs"
            >
              {endpoint(target.ip, target.port)}
            </bdi>
          </span>
          <span className="text-xs text-muted-foreground">
            {t("weight")}: <bdi>{target.weight}</bdi>
          </span>
        </li>
      ))}
      {connection.targets.length > limit && (
        <li className="text-xs text-muted-foreground">
          {t("clickAllDestinations")}
        </li>
      )}
    </ul>
  );
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <Tooltip open={!open && tooltipOpen} onOpenChange={setTooltipOpen}>
        <TooltipTrigger asChild>
          <PopoverTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-auto max-w-full flex-wrap justify-start gap-2 px-0 py-1 hover:bg-transparent"
              aria-label={`${t("viewDestinations")} · ${connection.name}`}
            >
              <bdi
                dir="ltr"
                className="max-w-full break-all whitespace-normal font-mono text-xs"
              >
                {endpoint(first.ip, first.port)}
              </bdi>
              <Badge variant="secondary">
                <bdi>+{connection.targets.length - 1}</bdi>
              </Badge>
              <ChevronDown data-icon="inline-end" />
            </Button>
          </PopoverTrigger>
        </TooltipTrigger>
        <TooltipContent className="block max-w-[calc(100vw-2rem)] bg-popover p-4 text-popover-foreground">
          {list(5)}
        </TooltipContent>
      </Tooltip>
      <PopoverContent
        className="w-88 max-w-[calc(100vw-2rem)] gap-4 p-4"
        align="start"
      >
        <div className="flex items-center justify-between">
          <span className="font-medium">{t("destinations")}</span>
          <HelpTip>{t("weightHelp")}</HelpTip>
        </div>
        {list(32)}
        <Badge variant="outline" className="w-fit">
          {t(connection.strategy)}
        </Badge>
      </PopoverContent>
    </Popover>
  );
}
