import { useContext, useState, type ReactNode } from "react";
import {
  FileCode2,
  History,
  Info,
  MoreHorizontal,
  RotateCcw,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
  Undo2,
} from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { PageTitle } from "@/components/shared";
import type { Inventory } from "@/lib/api";
import { number, trafficBytes } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import { useHealthView, useOptimizeView } from "@/features/operations/hooks";
import { Meter } from "./health/Indicators";
import { Confirm, type ConfirmRequest } from "./maintenance/Confirm";
import { ApplyDialog, type ApplyRequest } from "./optimize/ApplyDialog";
import { GroupRow } from "./optimize/GroupRow";
import { ProfilePicker } from "./optimize/ProfilePicker";
import {
  groupStates,
  managedKeys,
  outagesSinceApply,
  recommendedGroups,
  sameProfile,
  serverFit,
} from "./optimize/catalog";
import type {
  OptimizeGroup,
  OptimizeProfile,
  OptimizeView,
} from "./optimize/types";

function Fact({
  label,
  value,
  children,
}: {
  label: string;
  value: string;
  children?: ReactNode;
}) {
  return (
    <div className="opt-fact">
      <dt>{label}</dt>
      <dd>
        <bdi dir="ltr">{value}</bdi>
      </dd>
      {children}
    </div>
  );
}

/** Server facts beside the summary: memory, connection table use, TCP. */
function Facts({ view }: { view: OptimizeView }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const limit = Number(
    view.keys.find((k) => k.key === "net.netfilter.nf_conntrack_max")
      ?.current ?? 0,
  );
  const used =
    view.flows != null && limit ? (100 * view.flows) / limit : undefined;
  const congestion = view.keys.find(
    (k) => k.key === "net.ipv4.tcp_congestion_control",
  )?.current;
  return (
    <dl className="opt-facts">
      <Fact label={t("optMemory")} value={trafficBytes(view.memory, locale)} />
      <Fact
        label={t("optFlows")}
        value={
          view.flows == null
            ? "—"
            : `${number(view.flows, locale)} / ${limit ? number(limit, locale) : "—"}`
        }
      >
        <Meter value={used} label={t("optFlows")} />
      </Fact>
      <Fact label={t("optCongestion")} value={congestion || "—"} />
    </dl>
  );
}

/** Opt-in, reversible kernel settings for tunnel and forwarding servers. */
export function Optimize({
  inventory,
  run,
}: {
  inventory: Inventory;
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  // Unset until the user picks one: the page then shows the saved profile.
  const [picked, setPicked] = useState<OptimizeProfile>();
  const { value: view, error, reload } = useOptimizeView(picked);
  const { value: health } = useHealthView();
  const [review, setReview] = useState<OptimizeGroup[]>();
  const [confirm, setConfirm] = useState<ConfirmRequest>();
  const [open, setOpen] = useState<OptimizeGroup>();
  const [busy, setBusy] = useState(false);
  async function change(request: unknown) {
    setBusy(true);
    try {
      await run(request);
    } finally {
      setBusy(false);
      await reload();
    }
  }
  if (!view)
    return (
      <div className="page-stack">
        <PageTitle title={t("optimize")} description={t("optimizeIntro")} />
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : (
          <>
            <Skeleton className="h-36 w-full" />
            <Skeleton className="h-80 w-full" />
          </>
        )}
      </div>
    );
  const states = groupStates(view);
  const fit = serverFit(inventory, view);
  const recommended = recommendedGroups(states, fit);
  const improvements = states
    .filter((s) => recommended.includes(s.group))
    .reduce((sum, s) => sum + s.pending, 0);
  const applied = states.filter((s) => s.applied > 0).length;
  const managed = managedKeys(view);
  const selected = picked ?? view.profile;
  // Rows may still belong to the previous choice while the new one loads.
  const loading = !sameProfile(view.view, selected);
  const regressions = outagesSinceApply(
    view,
    health,
    health ? Date.parse(health.time) : 0,
  );
  const undo = () =>
    setConfirm({
      title: t("optUndoTitle"),
      body: t("optUndoBody"),
      action: t("optUndo"),
      run: () => change({ action: "optimize-undo" }),
    });
  const reset = () =>
    setConfirm({
      title: t("optResetTitle"),
      body: t("optResetBody").replace("{n}", String(managed.length)),
      action: t("optResetButton"),
      destructive: true,
      run: () =>
        change({ action: "optimize-remove", optimize: { group: "all" } }),
    });
  return (
    <div className="page-stack">
      <PageTitle
        title={t("optimize")}
        description={t("optimizeIntro")}
        action={
          <DropdownMenu dir={locale === "fa" ? "rtl" : "ltr"}>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" disabled={busy}>
                <MoreHorizontal data-icon="inline-start" />
                {t("optMore")}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="min-w-56">
              <DropdownMenuGroup>
                <DropdownMenuItem disabled={view.steps === 0} onSelect={undo}>
                  <Undo2 />
                  {t("optUndo")}
                </DropdownMenuItem>
              </DropdownMenuGroup>
              <DropdownMenuSeparator />
              <DropdownMenuGroup>
                <DropdownMenuItem
                  variant="destructive"
                  disabled={managed.length === 0}
                  onSelect={reset}
                >
                  <RotateCcw />
                  {t("optReset")}
                </DropdownMenuItem>
              </DropdownMenuGroup>
            </DropdownMenuContent>
          </DropdownMenu>
        }
      />
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <section className="opt-hero" data-state={improvements ? "open" : "done"}>
        <div className="opt-hero-main">
          <span className="opt-hero-icon">
            {improvements ? <Sparkles /> : <ShieldCheck />}
          </span>
          <div className="flex min-w-0 flex-col gap-1">
            <h2 className="opt-hero-title">
              {improvements
                ? t("optHeroTitle").replace("{n}", String(improvements))
                : t("optHeroNone")}
            </h2>
            <p className="text-sm text-muted-foreground">
              {t("optHeroProfile")
                .replace("{level}", t(`optLevel_${selected.level}`))
                .replace("{goal}", t(`optGoal_${selected.goal}`))}{" "}
              {t("optHeroDetail")
                .replace("{a}", String(applied))
                .replace("{g}", String(states.length))}
            </p>
          </div>
          {recommended.length > 0 && (
            <Button
              className="opt-hero-action"
              disabled={busy || loading}
              onClick={() => setReview(recommended)}
            >
              <Sparkles data-icon="inline-start" />
              {t("optReviewRecommended")}
            </Button>
          )}
        </div>
        <Facts view={view} />
      </section>
      {regressions.length > 0 && (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>
            {t("optRegressionTitle").replace("{n}", String(regressions.length))}
          </AlertTitle>
          <AlertDescription className="flex flex-col gap-3">
            <p>
              {t("optRegressionBody").replace(
                "{names}",
                [...new Set(regressions.map((o) => o.name))].join(
                  locale === "fa" ? "، " : ", ",
                ),
              )}
            </p>
            <div>
              <Button
                variant="outline"
                size="sm"
                disabled={busy}
                onClick={undo}
              >
                <Undo2 data-icon="inline-start" />
                {t("optUndo")}
              </Button>
            </div>
          </AlertDescription>
        </Alert>
      )}
      <ProfilePicker
        selected={selected}
        saved={view.profile}
        hasApplied={managed.length > 0}
        capped={view.capped}
        loading={loading}
        onChange={setPicked}
      />
      {view.servertools.length > 0 && (
        <Alert>
          <TriangleAlert />
          <AlertTitle>{t("optServerToolsTitle")}</AlertTitle>
          <AlertDescription>
            <p>{t("optServerToolsBody")}</p>
          </AlertDescription>
        </Alert>
      )}
      {view.import && (
        <Alert>
          <Info />
          <AlertTitle>{t("optImportTitle")}</AlertTitle>
          <AlertDescription>{t("optImportBody")}</AlertDescription>
        </Alert>
      )}
      <div className="opt-layout">
        <ul className="opt-rows" aria-label={t("optimize")} aria-busy={loading}>
          {states.map((state) => (
            <GroupRow
              key={state.group}
              state={state}
              fits={fit.has(state.group)}
              open={open === state.group}
              busy={busy || loading}
              toggle={() =>
                setOpen(open === state.group ? undefined : state.group)
              }
              review={() => setReview([state.group])}
              restore={() =>
                setConfirm({
                  title: t("optRestoreGroupTitle").replace(
                    "{group}",
                    t(`optGroup_${state.group}`),
                  ),
                  body: t("optRestoreGroupBody"),
                  action: t("optRestoreGroup"),
                  run: () =>
                    change({
                      action: "optimize-remove",
                      optimize: { group: state.group },
                    }),
                })
              }
            />
          ))}
        </ul>
        <aside className="opt-aside">
          <section className="opt-side-card">
            <h2>
              <ShieldCheck className="size-4" aria-hidden />
              {t("optSafetyTitle")}
            </h2>
            <ul>
              <li>{t("optSafety1")}</li>
              <li>{t("optSafety2")}</li>
              <li>{t("optSafety3")}</li>
            </ul>
          </section>
          <section className="opt-side-card">
            <h2>
              <History className="size-4" aria-hidden />
              {t("optHistoryTitle")}
            </h2>
            <p>
              {t("optHistoryBody")
                .replace("{n}", number(managed.length, locale))
                .replace("{s}", number(view.steps, locale))}
            </p>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={busy || view.steps === 0}
                onClick={undo}
              >
                <Undo2 data-icon="inline-start" />
                {t("optUndo")}
              </Button>
            </div>
          </section>
          <section className="opt-side-card">
            <h2>
              <FileCode2 className="size-4" aria-hidden />
              {t("optFilesTitle")}
            </h2>
            <code dir="ltr">{view.file}</code>
            {view.servertools.map((file) => (
              <code key={file} dir="ltr" className="opt-warn">
                {file}
              </code>
            ))}
          </section>
        </aside>
      </div>
      <ApplyDialog
        groups={review}
        profile={selected}
        onClose={() => setReview(undefined)}
        apply={({ groups, set, allowWorse }: ApplyRequest) =>
          change({
            action: "optimize-apply",
            optimize: {
              groups,
              level: selected.level,
              goal: selected.goal,
              set,
              allow_worse: allowWorse,
            },
          })
        }
      />
      <Confirm request={confirm} onClose={() => setConfirm(undefined)} />
    </div>
  );
}
