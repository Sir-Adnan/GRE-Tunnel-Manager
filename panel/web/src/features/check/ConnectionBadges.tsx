// Small badges under a connection's name: the source address the
// destination sees and the firewall's effect, linking to the Firewall page.
import { useContext } from "react";
import {
  Ban,
  ListChecks,
  Gauge,
  ShieldAlert,
  UserRound,
  Server,
  type LucideIcon,
} from "lucide-react";
import { LocaleContext, useT } from "@/lib/i18n";
import { number } from "@/lib/format";
import { routeURL } from "@/lib/navigation";
import type { FirewallStatus } from "@/features/firewall/model";
import { connectionBadges, type ConnectionBadge } from "./badges";

const icons: Record<ConnectionBadge["key"], LucideIcon> = {
  cbSourceServer: Server,
  cbSourceClient: UserRound,
  cbForwardBlocked: ShieldAlert,
  cbUFWClosed: Ban,
  cbAllow: ListChecks,
  cbDeny: Ban,
  cbLimited: Gauge,
};

export function ConnectionBadges({
  row,
  firewall,
}: {
  row: Parameters<typeof connectionBadges>[0];
  firewall?: FirewallStatus;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const badges = connectionBadges(row, firewall);
  if (!badges.length) return null;
  const href = routeURL(
    "firewall",
    new URLSearchParams({ connection: row.id }),
  );
  return (
    <span className="conn-badges">
      {badges.map((b) => {
        const Icon = icons[b.key];
        const label =
          b.count === undefined
            ? t(b.key)
            : `${t(b.key)} · ${number(b.count, locale)}`;
        const content = (
          <>
            <Icon aria-hidden />
            {label}
          </>
        );
        return b.firewall ? (
          <a
            key={b.key}
            href={href}
            className="conn-badge"
            data-tone={b.tone}
            title={t("cbFirewallHelp")}
          >
            {content}
          </a>
        ) : (
          <span key={b.key} className="conn-badge" title={t("cbSourceHelp")}>
            {content}
          </span>
        );
      })}
    </span>
  );
}
