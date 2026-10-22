import { useContext, useState } from "react";
import { Pencil, Play, Search, Square, Trash2, FileText } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ActionButton, HelpTip } from "@/components/help";
import { engineName, number } from "@/lib/format";
import { LocaleContext } from "@/lib/i18n";
import { Blank, Status } from "@/components/shared";
import { endpoint } from "@/lib/api";
import type { Connection } from "@/lib/api";
import { useT } from "@/lib/i18n";

export function ConnectionTable({
  connections,
  onAdd,
  onEdit,
  run,
  compact = false,
}: {
  connections: Connection[];
  onAdd: () => void;
  onEdit: (value: Connection) => void;
  run: (request: unknown) => Promise<void>;
  compact?: boolean;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [deleting, setDeleting] = useState(false);
  const [busy, setBusy] = useState(false);
  const shown = connections.filter((row) =>
    `${row.name} ${row.id} ${row.engine} ${row.ports} ${row.targets.map((target) => target.ip).join(" ")}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const picked = connections.filter((row) => selected.includes(row.id));
  async function action(operation: string, rows = picked) {
    setBusy(true);
    try {
      await run({
        action: operation,
        selected: rows.map((row) => ({ id: row.id, revision: row.revision })),
      });
      setSelected([]);
      setDeleting(false);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="flex flex-col gap-4">
      {!compact && (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="relative w-full sm:w-80">
            <Search className="pointer-events-none absolute start-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              aria-label={t("search")}
              placeholder={t("search")}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              className="ps-9"
            />
          </div>
          {picked.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-muted-foreground">
                {number(picked.length, locale)}
              </span>
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => void action("enable").catch(() => {})}
              >
                <Play data-icon="inline-start" />
                {t("enable")}
              </Button>
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => void action("disable").catch(() => {})}
              >
                <Square data-icon="inline-start" />
                {t("disable")}
              </Button>
              <Button
                variant="destructive"
                disabled={busy}
                onClick={() => setDeleting(true)}
              >
                <Trash2 data-icon="inline-start" />
                {t("delete")}
              </Button>
            </div>
          )}
        </div>
      )}
      {shown.length === 0 ? (
        <Blank onAdd={onAdd} filtered={query !== ""} />
      ) : (
        <div className="table-frame">
          <Table>
            <TableHeader>
              <TableRow>
                {!compact && (
                  <TableHead className="w-10">
                    <Checkbox
                      aria-label={t("selectAll")}
                      checked={
                        shown.length > 0 &&
                        shown.every((row) => selected.includes(row.id))
                          ? true
                          : shown.some((row) => selected.includes(row.id))
                            ? "indeterminate"
                            : false
                      }
                      onCheckedChange={(checked) =>
                        setSelected(
                          checked
                            ? [
                                ...new Set([
                                  ...selected,
                                  ...shown.map((row) => row.id),
                                ]),
                              ]
                            : selected.filter(
                                (id) => !shown.some((row) => row.id === id),
                              ),
                        )
                      }
                    />
                  </TableHead>
                )}
                <TableHead>{t("name")}</TableHead>
                <TableHead>{t("listener")}</TableHead>
                <TableHead>{t("destination")}</TableHead>
                <TableHead>{t("status")}</TableHead>
                <TableHead className="text-end">{t("actions")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.slice(0, compact ? 5 : 1000).map((row) => (
                <TableRow key={row.id}>
                  {!compact && (
                    <TableCell>
                      <Checkbox
                        checked={selected.includes(row.id)}
                        aria-label={`${t("selectAll")} ${row.name}`}
                        onCheckedChange={(checked) =>
                          setSelected(
                            checked
                              ? [...selected, row.id]
                              : selected.filter((id) => id !== row.id),
                          )
                        }
                      />
                    </TableCell>
                  )}
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <span className="engine-icon" aria-hidden>
                        {row.engine === "haproxy"
                          ? "H"
                          : row.engine === "realm"
                            ? "R"
                            : "N"}
                      </span>
                      <div className="flex flex-col gap-1">
                        <span className="font-medium">{row.name}</span>
                        <span className="flex items-center gap-1 text-xs text-muted-foreground">
                          <bdi>{engineName(row.engine)}</bdi>
                          <HelpTip
                            label={t("connectionID")}
                          >{`${t("connectionID")}: ${row.id}`}</HelpTip>
                        </span>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col gap-1">
                      <code dir="ltr">:{row.ports}</code>
                      <span className="text-xs text-muted-foreground" dir="ltr">
                        {row.protocol.toUpperCase()}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col gap-1">
                      <code dir="ltr">
                        {endpoint(row.targets[0].ip, row.targets[0].port)}
                      </code>
                      {row.targets.length > 1 && (
                        <span className="text-xs text-muted-foreground">
                          +{row.targets.length - 1} · {t(row.strategy)}
                        </span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Status
                      value={
                        row.status || (row.enabled ? "configured" : "disabled")
                      }
                    />
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center justify-end gap-1">
                      <ActionButton
                        variant="ghost"
                        size="icon"
                        label={`${t("edit")} ${row.name}`}
                        disabled={busy}
                        onClick={() => onEdit(row)}
                      >
                        <Pencil />
                      </ActionButton>
                      {!compact && (
                        <>
                          <ActionButton
                            variant="ghost"
                            size="icon"
                            label={`${t(row.enabled ? "disable" : "enable")} ${row.name}`}
                            disabled={busy}
                            onClick={() =>
                              void action(row.enabled ? "disable" : "enable", [
                                row,
                              ]).catch(() => {})
                            }
                          >
                            {row.enabled ? <Square /> : <Play />}
                          </ActionButton>
                          {["realm", "haproxy"].includes(row.engine) && (
                            <ActionButton
                              variant="ghost"
                              size="icon"
                              label={t("logs")}
                              onClick={() =>
                                void run({
                                  action: "logs",
                                  service: `gtm-${row.id}`,
                                }).catch(() => {})
                              }
                            >
                              <FileText />
                            </ActionButton>
                          )}
                          <ActionButton
                            variant="ghost"
                            size="icon"
                            label={`${t("delete")} ${row.name}`}
                            disabled={busy}
                            onClick={() => {
                              setSelected([row.id]);
                              setDeleting(true);
                            }}
                          >
                            <Trash2 />
                          </ActionButton>
                        </>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <Dialog
        open={deleting}
        onOpenChange={(open) => !busy && setDeleting(open)}
      >
        <DialogContent closeLabel={t("close")}>
          <DialogHeader>
            <DialogTitle>{t("confirmDelete")}</DialogTitle>
            <DialogDescription>{t("deleteDesc")}</DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-2">
            {picked.map((row) => (
              <code key={row.id} dir="ltr">
                {row.id} · {row.name} · :{row.ports}
              </code>
            ))}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setDeleting(false)}
            >
              {t("cancel")}
            </Button>
            <Button
              variant="destructive"
              disabled={busy || picked.length === 0}
              onClick={() => void action("delete").catch(() => {})}
            >
              {t(busy ? "working" : "delete")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
