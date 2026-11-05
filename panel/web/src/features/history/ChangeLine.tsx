import { useContext } from "react";
import { CircleMinus, CirclePlus, PencilLine } from "lucide-react";
import { EngineGlyph } from "@/components/shared";
import { LocaleContext, useT } from "@/lib/i18n";
import type { HistoryChange } from "./types";

const kindIcon = {
  added: CirclePlus,
  removed: CircleMinus,
  changed: PencilLine,
} as const;

/** One changed connection: what happened and which fields. */
export function ChangeLine({ change }: { change: HistoryChange }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const Icon = kindIcon[change.kind];
  return (
    <li className="hist-change" data-kind={change.kind}>
      <Icon className="hist-change-icon" aria-hidden />
      <span className="sr-only">{t(`histKind_${change.kind}`)}</span>
      <EngineGlyph engine={change.engine} />
      <span className="min-w-0 flex-1">
        <bdi className="hist-change-name">{change.name || change.id}</bdi>
        <span className="hist-change-what">
          {change.kind === "changed" && change.fields?.length
            ? change.fields
                .map((f) => t(`histField_${f}`))
                .join(locale === "fa" ? "، " : ", ")
            : t(`histKind_${change.kind}`)}
        </span>
      </span>
      <code dir="ltr" className="hist-change-id">
        {change.id}
      </code>
    </li>
  );
}

