import { useEffect, useMemo, useRef, useState } from "react";
import type { KeyboardEvent, ReactNode } from "react";
import {
  ChevronLeft,
  ChevronRight,
  CornerDownLeft,
  Search,
} from "lucide-react";
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
  /** A second step: choosing this command lists these instead of running. */
  children?: Command[];
  run?: () => void;
};

/**
 * A keyboard-first launcher (Ctrl/⌘+K) over navigation, creation, appearance
 * and saved connections. A command with `children` opens a second step (a
 * connection, then what to do with it); Backspace on an empty search or Escape
 * goes back.
 */
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
  const [parentId, setParentId] = useState<string>();
  const list = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  // Looked up by id so a refreshed inventory updates the open step.
  const parent = parentId
    ? commands.find((command) => command.id === parentId)
    : undefined;
  const matches = useMemo(
    () => matchCommands(parent?.children ?? commands, query).slice(0, 40),
    [commands, parent, query],
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
    setParentId(undefined);
  }
  function step(id?: string) {
    setParentId(id);
    setQuery("");
    setActive(0);
    input.current?.focus();
  }
  function choose(command?: Command) {
    if (!command) return;
    if (command.children) return step(command.id);
    close();
    command.run?.();
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
    } else if (event.key === "Backspace" && !query && parent) {
      event.preventDefault();
      step();
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
        mobileLayout="dialog"
        className="command-palette"
        onEscapeKeyDown={(event) => {
          if (!parent) return;
          event.preventDefault();
          step();
        }}
      >
        <DialogTitle className="sr-only">{t("commandPalette")}</DialogTitle>
        <DialogDescription className="sr-only">
          {t("commandPaletteHelp")}
        </DialogDescription>
        <div className="command-input">
          {parent ? (
            <button
              type="button"
              className="command-crumb"
              onClick={() => step()}
              aria-label={`${t("commandBack")}: ${parent.label}`}
            >
              <ChevronLeft className="size-3.5 rtl:rotate-180" />
              <bdi className="truncate">{parent.label}</bdi>
            </button>
          ) : (
            <Search className="size-4 shrink-0 text-muted-foreground" />
          )}
          <input
            ref={input}
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
                  {command.children ? (
                    <ChevronRight className="size-3.5 shrink-0 text-muted-foreground rtl:rotate-180" />
                  ) : (
                    index === current && (
                      <CornerDownLeft className="size-3.5 shrink-0 text-muted-foreground" />
                    )
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
          {parent && (
            <span>
              <kbd className="kbd">⌫</kbd> {t("commandBack")}
            </span>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
