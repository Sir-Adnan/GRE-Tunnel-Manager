// A connection's destinations in its route: one address (tap to copy) or the
// first with a count that opens the full list, each address copyable there.
import { useState } from "react";
import { ChevronDown, Copy, Server } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Popover,
  PopoverTrigger,
  PopoverContent,
} from "@/components/ui/popover";
import { HelpTip } from "@/components/help";
import { copyText } from "@/lib/clipboard";
import { endpointText } from "@/lib/format";

import type { Connection } from "@/lib/api";
import { useT } from "@/lib/i18n";

/**
 * An address never breaks inside an IPv4 address or a port: the only break
 * is between the two. Long IPv6 addresses may still break at any point.
 */
export function Endpoint({ ip, port }: { ip: string; port: number }) {
  const v6 = ip.includes(":");
  return (
    <bdi dir="ltr" className="endpoint-value" data-v6={v6 || undefined}>
      <span>{v6 ? `[${ip}]` : ip}</span>
      <wbr />
      <span>:{port}</span>
    </bdi>
  );
}

function useCopy() {
  const t = useT();
  return async (text: string) => {
    if (await copyText(text)) toast.success(`${t("copied")}: ${text}`);
    else toast.error(t("copyFailed"));
  };
}

export function Destinations({ connection }: { connection: Connection }) {
  const t = useT(),
    copy = useCopy(),
    [open, setOpen] = useState(false);
  const first = connection.targets[0];
  if (!first) return <span>—</span>;
  if (connection.targets.length === 1)
    return (
      <button
        type="button"
        className="endpoint-copy"
        aria-label={`${t("copy")} ${endpointText(first.ip, first.port)}`}
        title={t("copy")}
        onClick={() => void copy(endpointText(first.ip, first.port))}
      >
        <Endpoint ip={first.ip} port={first.port} />
        <Copy aria-hidden className="endpoint-copy-icon" />
      </button>
    );
  const list = (limit: number, copyable: boolean) => (
    <ul
      className="flex max-h-64 flex-col gap-1 overflow-y-auto"
      aria-label={t("destinations")}
    >
      {connection.targets.slice(0, limit).map((target, i) => (
        <li key={i} className="flex min-w-0 items-center justify-between gap-3">
          <span className="inline-flex min-w-0 items-center gap-2 py-1">
            <Server className="size-3.5 shrink-0 text-muted-foreground" />
            <span className="font-mono text-xs">
              <Endpoint ip={target.ip} port={target.port} />
            </span>
          </span>
          <span className="flex shrink-0 items-center gap-1 text-xs text-muted-foreground">
            {t("weight")}: <bdi>{target.weight}</bdi>
            {copyable && (
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                aria-label={`${t("copy")} ${endpointText(target.ip, target.port)}`}
                onClick={() => void copy(endpointText(target.ip, target.port))}
              >
                <Copy />
              </Button>
            )}
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
      <PopoverTrigger asChild>
        <button
          type="button"
          className="endpoint-copy"
          aria-label={`${t("viewDestinations")} · ${connection.name}`}
          aria-expanded={open}
        >
          <Endpoint ip={first.ip} port={first.port} />
          <Badge variant="secondary" className="shrink-0">
            <bdi>+{connection.targets.length - 1}</bdi>
          </Badge>
          <ChevronDown aria-hidden className="endpoint-copy-icon" />
        </button>
      </PopoverTrigger>
      {/* Focus the list itself, not its first control: that is the weight
          help, whose tooltip would otherwise open on top of the list. */}
      <PopoverContent
        className="w-88 max-w-[calc(100vw-2rem)] gap-3 p-4"
        align="start"
        onOpenAutoFocus={(event) => {
          event.preventDefault();
          (event.currentTarget as HTMLElement | null)?.focus?.();
        }}
      >
        <div className="flex items-center justify-between">
          <span className="font-medium">{t("destinations")}</span>
          <HelpTip>{t("weightHelp")}</HelpTip>
        </div>
        {list(32, true)}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <Badge variant="outline" className="w-fit">
            {t(connection.strategy)}
          </Badge>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() =>
              void copy(
                connection.targets
                  .map((x) => endpointText(x.ip, x.port))
                  .join("\n"),
              )
            }
          >
            <Copy data-icon="inline-start" />
            {t("copyAll")}
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}
