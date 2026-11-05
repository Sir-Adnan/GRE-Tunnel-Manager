import type { ReactNode } from "react";
import {
  ArrowRight,
  Check,
  CircleAlert,
  MinusCircle,
  PenLine,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { useT } from "@/lib/i18n";
import { compactValue, keyLabel } from "./catalog";
import type { Note } from "./types";

/** Now → recommended, or why nothing changes, for one sysctl key. */
export function ValueChange({
  setting,
  current,
  value,
  note,
}: {
  setting: string;
  current?: string;
  value?: string;
  note?: Note;
}) {
  const t = useT();
  if (note === "change" || note === "custom" || note === "worse")
    return (
      <span className="opt-change">
        <span className="opt-change" dir="ltr">
          <span className="opt-old">{compactValue(setting, current)}</span>
          <ArrowRight className="size-3.5 shrink-0 opacity-60" aria-hidden />
          <span className="opt-new" data-note={note}>
            {compactValue(setting, value)}
          </span>
        </span>
        {note === "custom" && (
          <span className="opt-note">
            <PenLine className="size-3.5" aria-hidden />
            {t("optCustom")}
          </span>
        )}
        {note === "worse" && (
          <span className="opt-note opt-warn">
            <TriangleAlert className="size-3.5" aria-hidden />
            {t("optWorse")}
          </span>
        )}
      </span>
    );
  return (
    <span className="opt-change">
      <bdi dir="ltr" className="opt-now">
        {compactValue(setting, current)}
      </bdi>
      {note === "kept" && (
        <span className="opt-note is-kept">
          <ShieldCheck className="size-3.5" aria-hidden />
          {t("optKept")}
        </span>
      )}
      {note === "same" && (
        <span className="opt-note is-same">
          <Check className="size-3.5" aria-hidden />
          {t("optSame")}
        </span>
      )}
      {note === "off" && (
        <span className="opt-note">
          <MinusCircle className="size-3.5" aria-hidden />
          {t("optOff")}
        </span>
      )}
      {note === "missing" && (
        <span className="opt-note">
          <CircleAlert className="size-3.5" aria-hidden />
          {t("optMissing")}
        </span>
      )}
    </span>
  );
}

/** One setting: friendly name, sysctl key, why, the change and its original value. */
export function SettingRow({
  setting,
  current,
  value,
  note,
  reason,
  before,
  managed,
  otherFile,
  otherValue,
  action,
  children,
}: {
  setting: string;
  current?: string;
  value?: string;
  note?: Note;
  reason?: string;
  before?: string;
  managed: boolean;
  otherFile?: string;
  otherValue?: string;
  /** A control beside the value, such as Edit in the review. */
  action?: ReactNode;
  /** Shown under the row, such as a custom-value editor. */
  children?: ReactNode;
}) {
  const t = useT();
  return (
    <li className="opt-setting" data-note={note} data-managed={managed}>
      <div className="opt-setting-name">
        <span className="text-sm font-medium">
          {t(keyLabel[setting] ?? setting)}
          {managed && (
            <span className="opt-managed" title={t("optManagedKey")}>
              {t("optManagedKey")}
            </span>
          )}
        </span>
        <code dir="ltr">{setting}</code>
        {reason && <span className="opt-why">{t(`optWhy_${reason}`)}</span>}
        {otherFile && (
          <span className="opt-why opt-warn">
            {/* File paths and values stay LTR inside either language. */}
            {t("optOther")
              .split(/(\{value\}|\{file\})/)
              .map((part, i) =>
                part === "{value}" || part === "{file}" ? (
                  <bdi key={i} dir="ltr" className="font-mono">
                    {part === "{value}" ? otherValue : otherFile}
                  </bdi>
                ) : (
                  part
                ),
              )}
          </span>
        )}
      </div>
      <div className="opt-setting-value">
        <ValueChange
          setting={setting}
          current={current}
          value={value}
          note={note}
        />
        {managed && before !== undefined && (
          <span className="opt-original">
            {t("optOriginalValue").replace("{v}", "")}
            <bdi dir="ltr">{compactValue(setting, before)}</bdi>
          </span>
        )}
        {action}
      </div>
      {children && <div className="opt-setting-editor">{children}</div>}
    </li>
  );
}
