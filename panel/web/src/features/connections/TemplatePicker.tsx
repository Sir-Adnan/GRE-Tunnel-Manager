// "Start from a template" on a new connection: one row of compact chips that
// fill the engine, protocol, ports and destination shape for a common setup.
// The chosen template's explanation shows under the row; phones scroll the
// row sideways so the fields stay in view.
import {
  Cable,
  Globe,
  Lock,
  Rows3,
  Split,
  type LucideIcon,
} from "lucide-react";
import { useT } from "@/lib/i18n";
import type { TemplateID } from "@/lib/templates";

const icons: Record<TemplateID, LucideIcon> = {
  vpn: Globe,
  web: Lock,
  range: Rows3,
  balance: Split,
  gre: Cable,
};

export function TemplatePicker({
  templates,
  value,
  onChange,
}: {
  templates: TemplateID[];
  value?: TemplateID;
  onChange: (id: TemplateID) => void;
}) {
  const t = useT();
  if (!templates.length) return null;
  return (
    <fieldset className="tpl-picker" aria-describedby="tpl-note">
      <legend className="tpl-legend">{t("tmplStart")}</legend>
      <div className="tpl-chips">
        {templates.map((id) => {
          const Icon = icons[id];
          return (
            <button
              key={id}
              type="button"
              className="tpl-chip"
              aria-pressed={value === id}
              title={t(`tmplHelp_${id}`)}
              onClick={() => onChange(id)}
            >
              <Icon aria-hidden />
              {t(`tmpl_${id}`)}
            </button>
          );
        })}
      </div>
      <p id="tpl-note" className="tpl-note" aria-live="polite">
        {value ? t(`tmplHelp_${value}`) : t("tmplPick")}
      </p>
    </fieldset>
  );
}
