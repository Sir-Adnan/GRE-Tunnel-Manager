import { useEffect, useMemo, useRef, useState } from "react";
import type { KeyboardEvent, ReactNode } from "react";
import { CornerDownLeft, Search } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "@/components/ui/dialog";
import { useT } from "@/lib/i18n";
import { matchCommands } from "@/lib/command-search";
import { cn } from "@/lib/utils";

export type Command = {
  id: string;
  group: string;
  label: string;
  /** Extra words that should find this command (engine names, English aliases...). */
  keywords?: string;
  hint?: string;
  icon?: ReactNode;
  run: () => void;
};

/** A keyboard-first launcher (Ctrl/⌘+K) over navigation, creation, appearance and saved connections. */
export function CommandPalette({
  open,
  onOpenChange,
  commands,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  commands: Command[];
}) {
  const t = useT();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const list = useRef<HTMLDivElement>(null);
  const matches = useMemo(
    () => matchCommands(commands, query).slice(0, 40),
    [commands, query],
  );
  const current = Math.min(active, Math.max(0, matches.length - 1));
  useEffect(() => {
    list.current
      ?.querySelector(`[data-index="${current}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [current]);
  function close() {
    onOpenChange(false);
    setQuery("");
    setActive(0);
  }
  function choose(command?: Command) {
    if (!command) return;
    close();
    command.run();
  }
  function keys(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      setActive(
        (current + step + matches.length) % Math.max(1, matches.length),
      );
    } else if (event.key === "Enter") {
      event.preventDefault();
      choose(matches[current]);
    }
  }
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => (next ? onOpenChange(true) : close())}
    >
      <DialogContent
        closeLabel={t("close")}
        showCloseButton={false}
        className="command-palette"
      >
        <DialogTitle className="sr-only">{t("commandPalette")}</DialogTitle>
        <DialogDescription className="sr-only">
          {t("commandPaletteHelp")}
        </DialogDescription>
        <div className="command-input">
          <Search className="size-4 shrink-0 text-muted-foreground" />
          <input
            autoFocus
            role="combobox"
            aria-expanded
            aria-controls="command-list"
            aria-activedescendant={
              matches[current] ? `command-${matches[current].id}` : undefined
            }
            aria-label={t("commandPalette")}
            placeholder={t("commandPlaceholder")}
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setActive(0);
            }}
            onKeyDown={keys}
          />
          <kbd className="kbd">Esc</kbd>
        </div>
        <div
          id="command-list"
          role="listbox"
          aria-label={t("commandPalette")}
          ref={list}
          className="command-list"
        >
          {matches.length === 0 && (
            <p className="px-3 py-8 text-center text-sm text-muted-foreground">
              {t("noMatch")}
            </p>
          )}
          {matches.map((command, index) => {
            const heading =
              index === 0 || matches[index - 1].group !== command.group;
            return (
              <div key={command.id} role="presentation">
                {heading && (
                  <div className="command-group" role="presentation">
                    {command.group}
                  </div>
                )}
                <div
                  id={`command-${command.id}`}
                  role="option"
                  aria-selected={index === current}
                  data-index={index}
                  className={cn(
                    "command-item",
                    index === current && "is-active",
                  )}
                  onMouseMove={() => index !== current && setActive(index)}
                  onClick={() => choose(command)}
                >
                  <span className="command-icon">{command.icon}</span>
                  <span className="min-w-0 flex-1 truncate">
                    {command.label}
                  </span>
                  {command.hint && (
                    <span className="command-hint">
                      <bdi>{command.hint}</bdi>
                    </span>
                  )}
                  {index === current && (
                    <CornerDownLeft className="size-3.5 shrink-0 text-muted-foreground" />
                  )}
                </div>
              </div>
            );
          })}
        </div>
        <div className="command-footer">
          <span>
            <kbd className="kbd">↑</kbd>
            <kbd className="kbd">↓</kbd> {t("commandNavigate")}
          </span>
          <span>
            <kbd className="kbd">Enter</kbd> {t("commandRun")}
          </span>
        </div>
      </DialogContent>
    </Dialog>
  );
}
