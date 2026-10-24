import { useContext, useState } from "react";
import {
  Play,
  Search,
  Square,
  Trash2,
  Workflow,
  Network,
  Route,
} from "lucide-react";
import { usePanelRoute } from "@/lib/use-panel-route";
import { Choice } from "@/components/shared";
import { ConnectionDetails } from "./ConnectionDetails";
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
import { HelpTip } from "@/components/help";
import { engineName, number } from "@/lib/format";
import { LocaleContext } from "@/lib/i18n";
import { Blank, Status } from "@/components/shared";
import { Destinations } from "./Destinations";
import { ConnectionActions } from "./ConnectionActions";
import { ConfigurationDialog } from "../configuration/ConfigurationDialog";
import type { Connection } from "@/lib/api";
import { useT } from "@/lib/i18n";

export function ConnectionTable({
  connections,
  onAdd,
  onEdit,
  run,
}: {
  connections: Connection[];
  onAdd: () => void;
  onEdit: (value: Connection) => void;
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [config, setConfig] = useState<Connection>();
  const { params, updateParams } = usePanelRoute();
  const query = params.get("q") || "";
  const statusFilter = params.get("status") || "all";
  const setQuery = (q: string) => updateParams({ q });
  const details = connections.find((c) => c.id === params.get("connection"));
  const closeDetails = () => updateParams({ connection: "", detail: "" });
  const [selected, setSelected] = useState<string[]>([]);
  const [deleting, setDeleting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [pageIndex, setPageIndex] = useState(0);
  const shown = connections.filter(
    (row) =>
      (statusFilter === "all" ||
        (row.status || (row.enabled ? "configured" : "disabled")) ===
          statusFilter) &&
      `${row.name} ${row.id} ${row.engine} ${row.ports} ${row.targets.map((target) => target.ip).join(" ")}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  const pageCount = Math.max(1, Math.ceil(shown.length / 20)),
    currentPage = Math.min(pageIndex, pageCount - 1);
  const visible = shown.slice(currentPage * 20, (currentPage + 1) * 20);
  const actions = (row: Connection) => (
    <ConnectionActions
      row={row}
      busy={busy}
      onConfig={() => setConfig(row)}
      onDetails={() => updateParams({ connection: row.id }, true)}
      onEdit={onEdit}
      onDelete={() => {
        setSelected([row.id]);
        setDeleting(true);
      }}
      onToggle={() =>
        void action(row.enabled ? "disable" : "enable", [row]).catch(() => {})
      }
      run={run}
    />
  );
  const glyph = (engine: string) => {
    const Icon =
      engine === "haproxy" ? Workflow : engine === "realm" ? Network : Route;
    return <Icon className="size-4" />;
  };
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
    <div className="@container flex min-w-0 flex-col gap-4">
      <div className="flex flex-wrap items-end gap-3">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute start-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            aria-label={t("search")}
            placeholder={t("search")}
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPageIndex(0);
            }}
            className="ps-9"
          />
        </div>
        <div className="w-full sm:w-44">
          <Choice
            id="connection-status"
            label={t("status")}
            value={statusFilter}
            onChange={(status) => {
              updateParams({ status: status === "all" ? "" : status });
              setPageIndex(0);
            }}
            choices={["all", "active", "configured", "disabled"].map((id) => ({
              value: id,
              label: t(id === "all" ? "allStatuses" : id),
            }))}
          />
        </div>
        <span className="text-xs text-muted-foreground">
          {number(shown.length, locale)} {t("connections")}
        </span>
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

      {shown.length === 0 ? (
        <Blank
          onAdd={onAdd}
          onReset={() => updateParams({ q: "", status: "" })}
          filtered={query !== "" || statusFilter !== "all"}
        />
      ) : (
        <>
          <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,22rem),1fr))] gap-3 @3xl:hidden">
            {visible.map((row) => (
              <article
                key={row.id}
                className="flex min-w-0 flex-col gap-3 rounded-xl border p-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex min-w-0 items-start gap-3">
                    <Checkbox
                      aria-label={`${t("selectConnection")} ${row.name}`}
                      checked={selected.includes(row.id)}
                      onCheckedChange={(v) =>
                        setSelected(
                          v
                            ? [...new Set([...selected, row.id])]
                            : selected.filter((id) => id !== row.id),
                        )
                      }
                    />

                    <div className="min-w-0">
                      <button
                        type="button"
                        className="connection-name"
                        onClick={() =>
                          updateParams({ connection: row.id }, true)
                        }
                      >
                        {row.name}
                      </button>
                      <span className="mt-1 inline-flex items-center gap-1.5 text-xs text-muted-foreground">
                        {glyph(row.engine)}
                        <bdi>{engineName(row.engine)}</bdi>
                      </span>
                    </div>
                  </div>
                  <Status
                    value={
                      row.status || (row.enabled ? "configured" : "disabled")
                    }
                  />
                </div>
                <dl className="grid min-w-0 grid-cols-[minmax(0,0.65fr)_minmax(0,1.35fr)] gap-3 text-sm">
                  <div className="flex min-w-0 flex-col gap-1">
                    <dt className="text-xs text-muted-foreground">
                      {t("listener")}
                    </dt>
                    <dd className="flex flex-wrap items-baseline gap-2">
                      <bdi dir="ltr" className="font-mono">
                        {row.ports}
                      </bdi>
                      <span className="text-xs text-muted-foreground">
                        {row.protocol.toUpperCase()}
                      </span>
                    </dd>
                  </div>
                  <div className="flex min-w-0 flex-col gap-1">
                    <dt className="text-xs text-muted-foreground">
                      {t("destination")}
                    </dt>
                    <dd className="min-w-0">
                      <Destinations connection={row} />
                    </dd>
                  </div>
                </dl>
                {actions(row)}
              </article>
            ))}
          </div>
          <div className="table-frame hidden @3xl:block">
            <Table className="table-fixed">
              <colgroup>
                <col style={{ width: 36 }} />
                <col />
                <col style={{ width: 88 }} />
                <col style={{ width: 190 }} />
                <col style={{ width: 100 }} />
                <col style={{ width: 98 }} />
              </colgroup>
              <TableHeader>
                <TableRow>
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

                  <TableHead>{t("name")}</TableHead>
                  <TableHead>{t("listener")}</TableHead>
                  <TableHead>{t("destination")}</TableHead>
                  <TableHead>{t("status")}</TableHead>
                  <TableHead className="text-end">{t("actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {visible.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell>
                      <Checkbox
                        checked={selected.includes(row.id)}
                        aria-label={`${t("selectConnection")} ${row.name}`}
                        onCheckedChange={(checked) =>
                          setSelected(
                            checked
                              ? [...selected, row.id]
                              : selected.filter((id) => id !== row.id),
                          )
                        }
                      />
                    </TableCell>

                    <TableCell>
                      <div className="flex min-w-0 items-center gap-3">
                        <span className="engine-icon" aria-hidden>
                          {glyph(row.engine)}
                        </span>
                        <div className="flex min-w-0 flex-col items-start gap-1">
                          <button
                            type="button"
                            className="connection-name"
                            onClick={() =>
                              updateParams({ connection: row.id }, true)
                            }
                          >
                            {row.name}
                          </button>
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
                      <div className="flex min-w-0 flex-col items-start gap-1">
                        <bdi
                          dir="ltr"
                          className="break-all whitespace-normal font-mono text-sm"
                        >
                          {row.ports}
                        </bdi>
                        <span
                          className="text-xs text-muted-foreground"
                          dir="ltr"
                        >
                          {row.protocol.toUpperCase()}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Destinations connection={row} />
                    </TableCell>
                    <TableCell>
                      <Status
                        value={
                          row.status ||
                          (row.enabled ? "configured" : "disabled")
                        }
                      />
                    </TableCell>
                    <TableCell>{actions(row)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </>
      )}
      {pageCount > 1 && (
        <div className="flex items-center justify-between gap-3">
          <span className="text-xs text-muted-foreground">
            <bdi>
              {currentPage + 1} / {pageCount}
            </bdi>
          </span>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={currentPage === 0}
              onClick={() => setPageIndex(currentPage - 1)}
            >
              {t("previousPage")}
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={currentPage === pageCount - 1}
              onClick={() => setPageIndex(currentPage + 1)}
            >
              {t("nextPage")}
            </Button>
          </div>
        </div>
      )}
      {details && (
        <ConnectionDetails
          row={details}
          onClose={closeDetails}
          onEdit={() => {
            closeDetails();
            onEdit(details);
          }}
          onConfig={() => {
            closeDetails();
            setConfig(details);
          }}
        />
      )}
      {config && (
        <ConfigurationDialog
          resource={config}
          run={run}
          onClose={() => setConfig(undefined)}
        />
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
