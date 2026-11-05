import { useContext, useState } from "react";
import { Search } from "lucide-react";
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
import { Blank, EngineGlyph, Status } from "@/components/shared";
import { Destinations } from "./Destinations";
import { ConnectionActions } from "./ConnectionActions";
import { SelectionBar } from "./SelectionBar";
import {
  connectionStatus,
  filterConnections,
  statusFilter,
  statusFilters,
} from "@/lib/connection-filters";
import { ConfigurationDialog } from "../configuration/ConfigurationDialog";
import type { Connection, Inventory } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { toast } from "sonner";
import { DragHandle, SortableArea, SortableItem } from "@/components/sortable";
import { applyOrder, mergeOrder, useOrder } from "@/lib/order";
import { useHealthView } from "@/features/operations/hooks";
import type { HealthStatus } from "@/features/operations/types";

/** A small health dot: up, degraded, down, unknown or not monitored. */
function HealthDot({ status }: { status?: HealthStatus | "off" }) {
  const t = useT();
  const value = status || "off";
  const label = value === "off" ? t("routeNotMonitored") : t(`health${value[0].toUpperCase()}${value.slice(1)}`);
  return <span className="health-dot" data-status={value} role="img" aria-label={label} title={label} />;
}

export function ConnectionTable({
  connections,
  onAdd,
  onEdit,
  onDuplicate,
  run,
  inventory,
}: {
  connections: Connection[];
  onAdd: () => void;
  onEdit: (value: Connection) => void;
  onDuplicate?: (value: Connection) => void;
  run: (request: unknown) => Promise<void>;
  inventory?: Inventory;
}) {
  const t = useT();
  const order = useOrder("connections");
  const health = useHealthView().value;
  const healthOf = (id: string): HealthStatus | "off" | undefined => {
    if (!health?.settings.enabled || health.settings.ignore?.includes(id)) return "off";
    return health.owners.find((o) => o.owner === id)?.status ?? "unknown";
  };
  const locale = useContext(LocaleContext);
  const [config, setConfig] = useState<Connection>();
  const { params, updateParams } = usePanelRoute();
  const query = params.get("q") || "";
  const status = statusFilter(params.get("status"));
  const setQuery = (q: string) => updateParams({ q });
  const details = connections.find((c) => c.id === params.get("connection"));
  const closeDetails = () => updateParams({ connection: "", detail: "" });
  const [selected, setSelected] = useState<string[]>([]);
  const [deleting, setDeleting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [pageIndex, setPageIndex] = useState(0);
  const shown = filterConnections(applyOrder(connections, order.ids, (c) => c.id), { status, query });
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
      onDuplicate={onDuplicate}
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
  const picked = connections.filter((row) => selected.includes(row.id));
  const visibleIds = visible.map((row) => row.id);
  // Reordering a filtered page moves those rows among their own positions in
  // the full, saved order (all engines).
  function move(next: string[]) {
    const everything = applyOrder(inventory?.connections ?? connections, order.ids, (c) => c.id).map((c) => c.id);
    void order.save(mergeOrder(everything, visibleIds, next)).then((e) => {
      if (e) toast.error(t("orderSaveFailed").replace("{e}", e));
    });
  }
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
        <div className="relative min-w-0 flex-1 basis-full sm:basis-40 sm:max-w-80">
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
        <div className="min-w-0 flex-1 sm:w-44 sm:flex-none">
          <Choice
            id="connection-status"
            label={t("status")}
            labelHidden
            value={status}
            onChange={(status) => {
              updateParams({ status: status === "all" ? "" : status });
              setPageIndex(0);
            }}
            choices={statusFilters.map((id) => ({
              value: id,
              label: t(id === "all" ? "allStatuses" : id),
            }))}
          />
        </div>
        <span className="shrink-0 text-xs text-muted-foreground">
          {number(shown.length, locale)} {t("connections")}
        </span>
      </div>

      {shown.length === 0 ? (
        <Blank
          onAdd={onAdd}
          onReset={() => updateParams({ q: "", status: "" })}
          filtered={query !== "" || status !== "all"}
        />
      ) : (
        <>
          <SortableArea ids={visibleIds} onMove={move}>
          <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,22rem),1fr))] gap-3 @3xl:hidden">
            {visible.map((row) => (
              <SortableItem key={row.id} id={row.id}>
              {(item) => (
              <article
                ref={item.setNodeRef}
                style={item.style}
                data-dragging={item.dragging || undefined}
                className="sortable-card flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex min-w-0 items-start gap-2">
                    <DragHandle handle={item.handle} label={row.name} className="!mt-0 -ms-1" />
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
                      <span className="flex items-center gap-2 text-xs text-muted-foreground">
                        <EngineGlyph engine={row.engine} />
                        <bdi>{engineName(row.engine)}</bdi>
                      </span>
                    </div>
                  </div>
                  <span className="flex items-center gap-2">
                    <HealthDot status={healthOf(row.id)} />
                    <Status value={connectionStatus(row)} />
                  </span>
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
              )}
              </SortableItem>
            ))}
          </div>
          </SortableArea>
          <div className="table-frame hidden @3xl:block">
            <Table className="table-fixed">
              <colgroup>
                <col style={{ width: 36 }} />
                <col style={{ width: 36 }} />
                <col style={{ width: "29%" }} />
                <col style={{ width: "12%" }} />
                <col />
                <col style={{ width: 112 }} />
                <col style={{ width: 148 }} />
              </colgroup>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-9">
                    <span className="sr-only">{t("dragHandle")}</span>
                  </TableHead>
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
              <SortableArea ids={visibleIds} onMove={move}>
              <TableBody>
                {visible.map((row) => (
                  <SortableItem key={row.id} id={row.id}>
                  {(item) => (
                  <TableRow ref={item.setNodeRef} style={item.style} data-dragging={item.dragging || undefined} className="sortable-row">
                    <TableCell className="px-1">
                      <DragHandle handle={item.handle} label={row.name} className="!mt-0" />
                    </TableCell>
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
                          <EngineGlyph engine={row.engine} />
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
                      <span className="flex items-center gap-2">
                        <HealthDot status={healthOf(row.id)} />
                        <Status value={connectionStatus(row)} />
                      </span>
                    </TableCell>
                    <TableCell>{actions(row)}</TableCell>
                  </TableRow>
                  )}
                  </SortableItem>
                ))}
              </TableBody>
              </SortableArea>
            </Table>
          </div>
        </>
      )}
      <SelectionBar
        count={picked.length}
        busy={busy}
        onEnable={() => void action("enable").catch(() => {})}
        onDisable={() => void action("disable").catch(() => {})}
        onDelete={() => setDeleting(true)}
        onClear={() => setSelected([])}
      />
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
