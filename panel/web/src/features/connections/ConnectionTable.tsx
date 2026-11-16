import { useContext, useEffect, useState } from "react";
import {
  ArrowUpDown,
  CheckSquare,
  MoreHorizontal,
  Pencil,
  Power,
  Search,
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
import { Blank, EngineGlyph, Status } from "@/components/shared";
import { RouteChain, StatusChip } from "./RouteChain";
import { ConnectionActions } from "./ConnectionActions";
import { SelectionBar } from "./SelectionBar";
import {
  connectionSort,
  connectionSorts,
  connectionStatus,
  filterConnections,
  sortConnections,
  statusFilter,
  statusFilters,
} from "@/lib/connection-filters";
import { ConfigurationDialog } from "../configuration/ConfigurationDialog";
import type { Connection, Inventory } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { toast } from "sonner";
import { ReorderList } from "@/components/ReorderList";
import { ConnectionCard } from "./ConnectionCard";
import { applyOrder, mergeOrder, useOrder } from "@/lib/order";
import { useHealthView, useLoaded } from "@/features/operations/hooks";
import { ConnectionBadges } from "@/features/check/ConnectionBadges";
import { connectionBadges, firewallChanged } from "@/features/check/badges";
import { connectionTone } from "@/lib/connection-tone";
import type { FirewallStatus } from "@/features/firewall/model";
import type { HealthStatus } from "@/features/operations/types";

/** A small health dot: up, degraded, down, unknown or not monitored. */
function HealthDot({ status }: { status?: HealthStatus | "off" }) {
  const t = useT();
  const value = status || "off";
  const label =
    value === "off"
      ? t("routeNotMonitored")
      : t(`health${value[0].toUpperCase()}${value.slice(1)}`);
  return (
    <span
      className="health-dot"
      data-status={value}
      role="img"
      aria-label={label}
      title={label}
    />
  );
}

const sortLabels = {
  custom: "sortCustom",
  name: "sortName",
  status: "sortStatus",
  engine: "sortEngine",
} as const;

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
  // Badges only; a host without the firewall report simply shows fewer.
  const { value: firewall, reload: reloadFirewall } = useLoaded<FirewallStatus>(
    "firewall",
    () => 60,
  );
  useEffect(() => {
    const changed = () => void reloadFirewall();
    window.addEventListener(firewallChanged, changed);
    return () => window.removeEventListener(firewallChanged, changed);
  }, [reloadFirewall]);
  const healthOf = (id: string): HealthStatus | "off" | undefined => {
    if (!health?.settings.enabled || health.settings.ignore?.includes(id))
      return "off";
    return health.owners.find((o) => o.owner === id)?.status ?? "unknown";
  };
  const toneOf = (row: Connection) =>
    connectionTone(
      { status: connectionStatus(row), enabled: row.enabled },
      healthOf(row.id),
      connectionBadges(row, firewall),
    );
  const locale = useContext(LocaleContext);
  const { params, updateParams } = usePanelRoute();
  // Dialogs opened by address, so the command palette and the back button reach them.
  const config = connections.find((c) => c.id === params.get("config"));
  const setConfig = (row?: Connection) =>
    updateParams({ config: row?.id ?? "" }, Boolean(row));
  // A delete asked for by address (the command palette) confirms that one row.
  const removing = connections.find((c) => c.id === params.get("remove"));
  const query = params.get("q") || "";
  const status = statusFilter(params.get("status"));
  const sort = connectionSort(params.get("sort"));
  const setQuery = (q: string) => updateParams({ q });
  const details = connections.find((c) => c.id === params.get("connection"));
  const closeDetails = () =>
    updateParams({ connection: "", detail: "", saved: "" });
  const [selected, setSelected] = useState<string[]>([]);
  const [deleting, setDeleting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [menuFor, setMenuFor] = useState<string>();
  // Phone cards show checkboxes only in selection mode (long press or
  // "Select"); the table always has them. Reordering is its own mode.
  const [selecting, setSelecting] = useState(false);
  const [reordering, setReordering] = useState(false);
  const [pageIndex, setPageIndex] = useState(0);
  const shown = filterConnections(
    sortConnections(
      applyOrder(connections, order.ids, (c) => c.id),
      sort,
      locale,
    ),
    { status, query },
  );
  const pageCount = Math.max(1, Math.ceil(shown.length / 20)),
    currentPage = Math.min(pageIndex, pageCount - 1);
  const visible = shown.slice(currentPage * 20, (currentPage + 1) * 20);
  const toggle = (row: Connection) =>
    void action(row.enabled ? "disable" : "enable", [row]).catch(() => {});
  // `swipe` marks the phone card, whose menu a swipe can also open.
  const actions = (row: Connection, swipe = false) => (
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
      onToggle={() => toggle(row)}
      run={run}
      {...(swipe && {
        menuOpen: menuFor === row.id,
        onMenuOpenChange: (open: boolean) =>
          setMenuFor(open ? row.id : undefined),
      })}
    />
  );
  const picked = connections.filter((row) => selected.includes(row.id));
  const doomed = removing ? [removing] : picked;
  const confirming = deleting || Boolean(removing);
  const stopDeleting = () => {
    setDeleting(false);
    updateParams({ remove: "" });
  };
  const shownIds = shown.map((row) => row.id);
  const isSelected = (id: string) => selected.includes(id);
  const setRowSelected = (id: string, on: boolean) =>
    setSelected((current) =>
      on ? [...new Set([...current, id])] : current.filter((x) => x !== id),
    );
  const stopSelecting = () => {
    setSelecting(false);
    setSelected([]);
  };
  // Escape leaves selection mode, as the bar's close button does.
  useEffect(() => {
    if (!selecting) return;
    const key = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !event.defaultPrevented) {
        setSelecting(false);
        setSelected([]);
      }
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [selecting]);
  const startReordering = () => {
    stopSelecting();
    // Reordering shows the custom order; a sort would hide each move.
    if (sort !== "custom") updateParams({ sort: "" });
    setReordering(true);
  };
  // Reordering a filtered list moves those rows among their own positions in
  // the full, saved order (all engines). Undo puts the previous order back.
  async function saveOrder(next: string[]) {
    const everything = applyOrder(
      inventory?.connections ?? connections,
      order.ids,
      (c) => c.id,
    ).map((c) => c.id);
    const failed = (e: string) =>
      toast.error(t("orderSaveFailed").replace("{e}", e));
    const e = await order.save(mergeOrder(everything, shownIds, next));
    if (e) return failed(e);
    setReordering(false);
    toast.success(t("orderSaved"), {
      action: {
        label: t("undo"),
        onClick: () => void order.save(everything).then((e) => e && failed(e)),
      },
    });
  }
  async function action(operation: string, rows = picked) {
    setBusy(true);
    try {
      await run({
        action: operation,
        selected: rows.map((row) => ({ id: row.id, revision: row.revision })),
      });
      stopSelecting();
      stopDeleting();
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="@container flex min-w-0 flex-col gap-4">
      {reordering ? (
        <ReorderList
          label={t("reorderConnections")}
          items={shown.map((row) => ({
            id: row.id,
            label: row.name,
            leading: <StatusChip tone={toneOf(row)} />,
            meta: (
              <>
                <EngineGlyph engine={row.engine} className="size-3.5" />
                <bdi>{engineName(row.engine)}</bdi>
                <bdi dir="ltr" className="font-mono">
                  {row.ports}
                </bdi>
              </>
            ),
          }))}
          onSave={saveOrder}
          onCancel={() => setReordering(false)}
        />
      ) : (
        <>
          <div className="connection-toolbar">
            <div className="connection-search">
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
            <div className="connection-filter">
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
            <div className="connection-filter">
              <Choice
                id="connection-sort"
                label={t("sortBy")}
                labelHidden
                value={sort}
                onChange={(sort) => {
                  updateParams({ sort: sort === "custom" ? "" : sort });
                  setPageIndex(0);
                }}
                choices={connectionSorts.map((id) => ({
                  value: id,
                  label: t(sortLabels[id]),
                }))}
              />
            </div>
            <div className="connection-toolbar-end">
              <span className="me-auto text-xs text-muted-foreground">
                {number(shown.length, locale)} {t("connections")}
              </span>
              {shown.length > 0 && (
                <Button
                  variant={selecting ? "secondary" : "outline"}
                  size="sm"
                  className="@3xl:hidden"
                  aria-pressed={selecting}
                  onClick={() =>
                    selecting ? stopSelecting() : setSelecting(true)
                  }
                >
                  <CheckSquare data-icon="inline-start" />
                  {t("selectMode")}
                </Button>
              )}
              {shown.length > 1 && (
                <Button variant="outline" size="sm" onClick={startReordering}>
                  <ArrowUpDown data-icon="inline-start" />
                  {t("reorder")}
                </Button>
              )}
            </div>
          </div>

          {shown.length === 0 ? (
            <Blank
              onAdd={onAdd}
              onReset={() => updateParams({ q: "", status: "" })}
              filtered={query !== "" || status !== "all"}
            />
          ) : (
            <>
              <div className="connection-cards @3xl:hidden">
                {visible.map((row) => (
                  <ConnectionCard
                    key={row.id}
                    row={row}
                    tone={toneOf(row)}
                    status={connectionStatus(row)}
                    health={<HealthDot status={healthOf(row.id)} />}
                    badges={<ConnectionBadges row={row} firewall={firewall} />}
                    actions={actions(row, true)}
                    swipe={{
                      end: [
                        {
                          id: "toggle",
                          label: t(row.enabled ? "turnOff" : "turnOn"),
                          icon: <Power />,
                          tone: row.enabled ? "warn" : "ok",
                          onSelect: () => !busy && toggle(row),
                        },
                        {
                          id: "edit",
                          label: t("edit"),
                          icon: <Pencil />,
                          tone: "primary",
                          onSelect: () => onEdit(row),
                        },
                      ],
                      start: [
                        {
                          id: "more",
                          label: t("moreNavigation"),
                          icon: <MoreHorizontal />,
                          onSelect: () => setMenuFor(row.id),
                        },
                      ],
                    }}
                    selecting={selecting}
                    selected={isSelected(row.id)}
                    onSelectedChange={(on) => setRowSelected(row.id, on)}
                    onStartSelecting={() => {
                      setSelecting(true);
                      setRowSelected(row.id, true);
                    }}
                    onOpen={() => updateParams({ connection: row.id }, true)}
                  />
                ))}
              </div>
              <div className="table-frame hidden @3xl:block">
                <Table className="table-fixed">
                  <colgroup>
                    <col style={{ width: 44 }} />
                    <col style={{ width: "26%" }} />
                    <col />
                    <col style={{ width: 128 }} />
                    <col style={{ width: 148 }} />
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
                      <TableHead>{t("route")}</TableHead>
                      <TableHead>{t("status")}</TableHead>
                      <TableHead className="text-end">{t("actions")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {visible.map((row) => (
                      <TableRow
                        key={row.id}
                        data-state={isSelected(row.id) ? "selected" : undefined}
                      >
                        <TableCell>
                          <Checkbox
                            checked={isSelected(row.id)}
                            aria-label={`${t("selectConnection")} ${row.name}`}
                            onCheckedChange={(checked) =>
                              setRowSelected(row.id, checked === true)
                            }
                          />
                        </TableCell>

                        <TableCell>
                          <div className="flex min-w-0 items-center gap-3">
                            <StatusChip tone={toneOf(row)} />
                            <div className="flex min-w-0 flex-col items-start gap-0.5">
                              <button
                                type="button"
                                className="connection-name bidi-name"
                                onClick={() =>
                                  updateParams({ connection: row.id }, true)
                                }
                              >
                                {row.name}
                              </button>
                              <span className="flex items-center gap-1 text-xs text-muted-foreground">
                                <EngineGlyph
                                  engine={row.engine}
                                  className="size-3.5"
                                />
                                <bdi>{engineName(row.engine)}</bdi>
                                <HelpTip
                                  label={t("connectionID")}
                                >{`${t("connectionID")}: ${row.id}`}</HelpTip>
                              </span>
                              <ConnectionBadges row={row} firewall={firewall} />
                            </div>
                          </div>
                        </TableCell>
                        <TableCell className="whitespace-normal">
                          <RouteChain connection={row} tone={toneOf(row)} />
                        </TableCell>
                        <TableCell>
                          <span className="flex items-center gap-2">
                            <HealthDot status={healthOf(row.id)} />
                            <Status
                              value={connectionStatus(row)}
                              tone={toneOf(row)}
                            />
                          </span>
                        </TableCell>
                        <TableCell>{actions(row)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </>
          )}
        </>
      )}
      <SelectionBar
        count={picked.length}
        open={selecting && !reordering}
        onSelectAll={
          shown.every((row) => isSelected(row.id))
            ? undefined
            : () => setSelected(shownIds)
        }
        busy={busy}
        onEnable={() => void action("enable").catch(() => {})}
        onDisable={() => void action("disable").catch(() => {})}
        onDelete={() => setDeleting(true)}
        onClear={stopSelecting}
      />
      {!reordering && pageCount > 1 && (
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
          hostname={inventory?.host.hostname ?? ""}
          run={run}
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
        open={confirming}
        onOpenChange={(open) =>
          !busy && (open ? setDeleting(true) : stopDeleting())
        }
      >
        <DialogContent closeLabel={t("close")}>
          <DialogHeader>
            <DialogTitle>{t("confirmDelete")}</DialogTitle>
            <DialogDescription>{t("deleteDesc")}</DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-2">
            {doomed.map((row) => (
              <code key={row.id} dir="ltr">
                {row.id} · {row.name} · :{row.ports}
              </code>
            ))}
          </div>
          <DialogFooter>
            <Button variant="outline" disabled={busy} onClick={stopDeleting}>
              {t("cancel")}
            </Button>
            <Button
              variant="destructive"
              disabled={busy || doomed.length === 0}
              onClick={() => void action("delete", doomed).catch(() => {})}
            >
              {t(busy ? "working" : "delete")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
