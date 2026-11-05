import { useContext, useState } from "react";
import {
  Bell,
  BellOff,
  CheckCheck,
  CircleAlert,
  CircleCheck,
  Settings2,
  Trash2,
  TriangleAlert,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { api } from "@/lib/api";
import { LocaleContext, useT } from "@/lib/i18n";
import { useNow } from "@/features/operations/hooks";
import {
  byDay,
  dayLabel,
  eventDetail,
  eventTarget,
  relative,
  unreadBadge,
} from "./catalog";
import { eventTitle, useNotifications } from "./hooks";
import type { NotifyEvent } from "./types";

const severityIcon = {
  critical: CircleAlert,
  warning: TriangleAlert,
  info: CircleCheck,
} as const;

function EventItem({
  event,
  now,
  open,
}: {
  event: NotifyEvent;
  now: number;
  open: (e: NotifyEvent) => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const Icon = severityIcon[event.severity] ?? CircleCheck;
  return (
    <li>
      <button
        type="button"
        className="ntf-item"
        data-severity={event.severity}
        data-read={event.read}
        onClick={() => open(event)}
      >
        <span className="ntf-icon" aria-hidden>
          <Icon />
        </span>
        <span className="ntf-body">
          <span className="ntf-title">
            <bdi>{eventTitle(event, t)}</bdi>
          </span>
          {(() => {
            const detail = eventDetail(event, t, locale);
            return (
              detail && (
                <span className="ntf-detail" dir="auto">
                  {detail}
                </span>
              )
            );
          })()}
          <span className="ntf-meta">
            <time dateTime={event.time} title={new Date(event.time).toLocaleString()}>
              {relative(event.time, now, locale)}
            </time>
            {event.delivery && event.delivery !== "pending" && (
              <span className="ntf-delivery" data-state={event.delivery}>
                {t(`ntfDelivery_${event.delivery}`)}
              </span>
            )}
          </span>
        </span>
        {!event.read && (
          <span className="ntf-unread-dot" aria-label={t("ntfUnread")} />
        )}
      </button>
    </li>
  );
}

/** Header bell and the notification sheet. */
export function NotificationCenter({
  navigate,
}: {
  navigate: (page: string, params?: Record<string, string>) => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { value, reload } = useNotifications();
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState<"all" | "unread">("all");
  const now = useNow(open);
  const unread = value?.unread ?? 0;
  const events = (value?.events ?? []).filter(
    (e) => filter === "all" || !e.read,
  );
  async function post(path: string, body: unknown) {
    try {
      await api(path, body);
      await reload();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  }
  function show(e: NotifyEvent) {
    if (!e.read) void post("notifications/read", { ids: [e.id] });
    const target = eventTarget(e);
    setOpen(false);
    navigate(target.page, target.params);
  }
  return (
    <>
      <Button
        variant="ghost"
        size="icon"
        className="relative"
        aria-label={
          unread
            ? t("ntfOpenUnread").replace("{n}", String(unread))
            : t("notifications")
        }
        onClick={() => setOpen(true)}
      >
        <Bell />
        {unread > 0 && (
          <span className="ntf-badge" aria-hidden>
            {unreadBadge(unread)}
          </span>
        )}
      </Button>
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent
          side={locale === "fa" ? "left" : "right"}
          closeLabel={t("close")}
          className="ntf-sheet data-[side=left]:w-[min(92vw,28rem)] data-[side=right]:w-[min(92vw,28rem)] data-[side=left]:sm:max-w-md data-[side=right]:sm:max-w-md"
          dir={locale === "fa" ? "rtl" : "ltr"}
        >
          <SheetHeader className="ntf-head">
            <SheetTitle>{t("notifications")}</SheetTitle>
            <SheetDescription>{t("ntfIntro")}</SheetDescription>
            <div className="ntf-toolbar">
              <ToggleGroup
                type="single"
                size="sm"
                variant="outline"
                value={filter}
                onValueChange={(v) => v && setFilter(v as "all" | "unread")}
                aria-label={t("ntfFilter")}
              >
                <ToggleGroupItem value="all">{t("ntfAll")}</ToggleGroupItem>
                <ToggleGroupItem value="unread">
                  {t("ntfUnreadOnly")}
                  {unread > 0 && <span className="ntf-count">{unread}</span>}
                </ToggleGroupItem>
              </ToggleGroup>
              <div className="flex items-center gap-1">
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={t("ntfMarkAll")}
                  title={t("ntfMarkAll")}
                  disabled={!unread}
                  onClick={() => void post("notifications/read", { all: true })}
                >
                  <CheckCheck />
                </Button>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={t("ntfClear")}
                  title={t("ntfClear")}
                  disabled={!value?.events.length}
                  onClick={() => void post("notifications/clear", {})}
                >
                  <Trash2 />
                </Button>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={t("ntfChannels")}
                  title={t("ntfChannels")}
                  onClick={() => {
                    setOpen(false);
                    navigate("settings", { section: "notifications" });
                  }}
                >
                  <Settings2 />
                </Button>
              </div>
            </div>
          </SheetHeader>
          <div className="ntf-scroll">
            {events.length === 0 ? (
              <div className="ntf-empty">
                <BellOff aria-hidden />
                <p>{filter === "unread" ? t("ntfNoneUnread") : t("ntfNone")}</p>
              </div>
            ) : (
              byDay(events).map((group) => (
                <section key={group.day} className="ntf-day">
                  <h3>{dayLabel(group.events[0].time, now, locale, t)}</h3>
                  <ul>
                    {group.events.map((e) => (
                      <EventItem key={e.id} event={e} now={now} open={show} />
                    ))}
                  </ul>
                </section>
              ))
            )}
          </div>
        </SheetContent>
      </Sheet>
    </>
  );
}
