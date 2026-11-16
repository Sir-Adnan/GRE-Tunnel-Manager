// Abuse protection: no new uplink traffic to private ranges or port 25.
import { useState } from "react";
import { HelpTip } from "@/components/help";
import { Switch } from "@/components/ui/switch";
import { useT } from "@/lib/i18n";
import {
  counter,
  parseSources,
  type FirewallSettings,
  type FirewallStatus,
} from "./model";
import { fill, useNumber } from "./text";

/** The engine's private ranges (GTM_GUARD_PRIVATE4/6 in src/guard.sh). */
const privateRanges = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "100.64.0.0/10",
  "fc00::/7",
];

export function Protection({
  status,
  settings,
  busy,
  change,
}: {
  status: FirewallStatus;
  settings: FirewallSettings;
  busy: boolean;
  change: (next: FirewallSettings) => void;
}) {
  const t = useT();
  const format = useNumber();
  const [text, setText] = useState(settings.exceptions.join("\n"));
  const { invalid } = parseSources(text);
  const uplinks = status.uplinks.length
    ? `⁦${status.uplinks.join(", ")}⁩`
    : t("fwNoUplink");
  const rows = [
    {
      key: "private_ranges",
      label: "fwPrivate",
      help: fill(t("fwPrivateHelp"), { u: uplinks }),
      rule: "private",
    },
    { key: "smtp", label: "fwSMTP", help: t("fwSMTPHelp"), rule: "smtp" },
  ] as const;
  return (
    <section className="fw-section" aria-labelledby="fw-protection">
      <div className="fw-section-head">
        <h2 id="fw-protection" className="fw-section-title">
          {t("fwProtection")}
        </h2>
      </div>
      <p className="text-sm text-muted-foreground">{t("fwProtectionIntro")}</p>
      <div className="fw-protect-card">
        {rows.map((row) => {
          const id = `fw-${row.rule}`;
          const blocked = counter(status, row.rule);
          return (
            <div key={row.key} className="fw-protect-row">
              <div className="min-w-0 flex-1">
                <label htmlFor={id} className="text-sm font-medium">
                  {t(row.label)}
                </label>
                <p className="text-xs leading-relaxed text-muted-foreground">
                  {row.help}
                </p>
                {row.rule === "private" && (
                  <span className="fw-chips mt-1.5">
                    {privateRanges.map((range) => (
                      <bdi key={range} dir="ltr" className="fw-chip font-mono">
                        {range}
                      </bdi>
                    ))}
                  </span>
                )}
                {settings[row.key] && blocked > 0 && (
                  <span className="fw-chip mt-1" data-tone="problem">
                    {fill(t("fwBlocked"), { n: format(blocked) })}
                  </span>
                )}
              </div>
              <Switch
                id={id}
                checked={settings[row.key]}
                disabled={busy}
                onCheckedChange={(value) =>
                  change({ ...settings, [row.key]: value })
                }
              />
            </div>
          );
        })}
        {settings.private_ranges && (
          <div className="fw-protect-row flex-col items-stretch">
            <div className="field-label-row">
              <label htmlFor="fw-exceptions" className="text-sm font-medium">
                {t("fwExceptions")}
              </label>
              <HelpTip label={`${t("fwExceptions")} · ?`}>
                {t("fwExceptionsHelp")}
              </HelpTip>
            </div>
            <textarea
              id="fw-exceptions"
              dir="ltr"
              rows={3}
              spellCheck={false}
              className="dns-textarea"
              value={text}
              disabled={busy}
              aria-invalid={invalid.length > 0}
              placeholder="10.202.10.10"
              onChange={(event) => {
                setText(event.target.value);
                const parsed = parseSources(event.target.value);
                if (parsed.invalid.length === 0)
                  change({ ...settings, exceptions: parsed.sources });
              }}
            />
            {invalid.length > 0 && (
              <p className="text-xs text-destructive" role="alert">
                {fill(t("fwSourcesInvalid"), {
                  s: invalid.slice(0, 3).join(", "),
                })}
              </p>
            )}
            {status.auto_exceptions.length > 0 && (
              <div className="flex flex-col gap-1.5">
                <span className="flex items-center gap-1 text-xs text-muted-foreground">
                  {t("fwAutoExceptions")}
                  <HelpTip label={`${t("fwAutoExceptions")} · ?`}>
                    {t("fwAutoExceptionsHelp")}
                  </HelpTip>
                </span>
                <span className="fw-chips">
                  {status.auto_exceptions.map((a) => (
                    <bdi key={a} dir="ltr" className="fw-chip font-mono">
                      {a}
                    </bdi>
                  ))}
                </span>
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
