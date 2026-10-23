import { useState, type ComponentProps } from "react";
import { CircleHelp } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { useT } from "@/lib/i18n";

/** Action labels remain available to keyboard users and on mouse hover. */
export function ActionButton({
  label,
  ...props
}: ComponentProps<typeof Button> & { label: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button aria-label={label} {...props} />
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}

/** Hover/focus previews the help; a click or tap opens persistent, dismissible help. */
export function HelpTip({
  children,
  label,
}: {
  children: string;
  label?: string;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [tooltipOpen, setTooltipOpen] = useState(false);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <Tooltip open={!open && tooltipOpen} onOpenChange={setTooltipOpen}>
        <TooltipTrigger asChild>
          <PopoverTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              aria-label={label || t("help")}
            >
              <CircleHelp />
            </Button>
          </PopoverTrigger>
        </TooltipTrigger>
        <TooltipContent>{children}</TooltipContent>
      </Tooltip>
      <PopoverContent
        className="max-w-[calc(100vw-2rem)] text-start text-sm leading-7"
        sideOffset={8}
      >
        {children}
      </PopoverContent>
    </Popover>
  );
}
