import { endpoint } from "@/lib/api";
import type { Connection } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { isHostname, parseSpans, remoteSpans, spanText, targetPorts } from "@/lib/ports";
export function ConnectionReview({
  value,
  resolved = {},
}: {
  value: Connection;
  resolved?: Record<string, string[] | null | undefined>;
}) {
  const t = useT();
  const kernel = value.engine === "nftables" || value.engine === "iptables";
  const spans = parseSpans(value.ports, kernel).spans;
  const remote = remoteSpans(spans, value.port_mode || "", value.remote_ports || "", 0);
  const mapped = value.port_mode ? remote.spans.map(spanText).join(", ") : "";
  return (
    <div className="review-block">
      <dl className="review-grid">
        <dt>{t("name")}</dt>
        <dd>{value.name || `${value.engine}-${value.ports.split(/[-,\s]/)[0]}`}</dd>
        <dt>{t("listener")}</dt>
        <dd>
          <code dir="ltr">
            {endpoint(value.bind, value.ports)} / {value.protocol.toUpperCase()}
          </code>
        </dd>
        <dt>{t("destination")}</dt>
        <dd className="flex flex-col gap-2">
          {value.targets.map((target, index) => (
            <div key={index} className="flex min-w-0 flex-col gap-0.5">
              <span className="flex flex-wrap items-baseline gap-x-2">
                <code dir="ltr">{endpoint(target.ip, mapped || targetPorts(target))}</code>
                {value.targets.length > 1 && (
                  <span className="text-xs text-muted-foreground">
                    {t("weight")} {target.weight}
                  </span>
                )}
              </span>
              {isHostname(target.ip) && (
                <span className="text-xs text-muted-foreground" dir="ltr">
                  {(resolved[target.ip] || []).join(", ") || t("dnsNoAddress")}
                </span>
              )}
            </div>
          ))}
        </dd>
        <dt>{t("strategy")}</dt>
        <dd>{t(value.strategy)}</dd>
        {value.engine === "haproxy" && (
          <>
            <dt>{t("healthProbe")}</dt>
            <dd>
              {t(
                value.options.check_mode === "off"
                  ? "off"
                  : value.options.check_mode === "http"
                    ? "httpReadiness"
                    : "tcpConnect",
              )}
            </dd>
          </>
        )}
        <dt>{t("status")}</dt>
        <dd>{t(value.enabled ? "willStart" : "willSaveDisabled")}</dd>
      </dl>
      {Object.keys(value.options).length > 0 && (
        <details className="rounded-lg border p-3">
          <summary className="cursor-pointer font-medium">
            {t("advanced")}
          </summary>
          <dl className="mt-3 grid gap-3 sm:grid-cols-2">
            {Object.entries(value.options).map(([key, option]) => (
              <div key={key} className="flex flex-col gap-1">
                <dt className="text-xs text-muted-foreground">{t(key)}</dt>
                <dd className="break-words">
                  <bdi>{t(option)}</bdi>
                </dd>
              </div>
            ))}
          </dl>
        </details>
      )}
      {value.routing && (
        <div className="mt-4 flex flex-col gap-3 rounded-xl border p-4">
          <p className="font-medium">{t(`routeMode_${value.routing.mode}`)}</p>
          {value.routing.certificate && (
            <p>
              {t("certificateID")}: <bdi>{value.routing.certificate}</bdi>
            </p>
          )}
          {value.routing.rules.map((rule, i) => {
            const destination = value.targets[rule.target - 1];
            return (
              <p key={i} className="break-words text-sm" dir="ltr">
                {rule.host}
                {rule.prefix || ""} →{" "}
                {destination
                  ? endpoint(destination.ip, destination.port)
                  : t("invalid")}
              </p>
            );
          })}
          <p className="text-xs text-muted-foreground">
            {t(value.routing.mode === "sni" ? "sniHelp" : "httpRoutingHelp")}
          </p>
        </div>
      )}
    </div>
  );
}
