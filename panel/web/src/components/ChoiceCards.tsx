import type { ReactNode } from "react";

export type ChoiceCard<T extends string> = {
  id: T;
  icon: ReactNode;
  title: string;
  help?: string;
  /** A short tag after the title, such as "Not installed". */
  note?: string;
};

/**
 * A small set of exclusive choices shown as cards (a native radio group, so
 * arrow keys move between them). Use it when each choice needs a line of
 * explanation; keep a select for long lists.
 */
export function ChoiceCards<T extends string>({
  name,
  label,
  value,
  choices,
  onChange,
  compact = false,
}: {
  /** The radio group's name, unique on the page. */
  name: string;
  label: string;
  value: T;
  choices: ChoiceCard<T>[];
  onChange: (next: T) => void;
  /** Phones: icon and text side by side, one choice per row. */
  compact?: boolean;
}) {
  return (
    <div
      className="choice-cards"
      data-compact={compact || undefined}
      role="radiogroup"
      aria-label={label}
    >
      {choices.map((choice) => (
        <label
          key={choice.id || "default"}
          className="choice-card"
          data-checked={value === choice.id || undefined}
        >
          <input
            type="radio"
            name={name}
            className="sr-only"
            checked={value === choice.id}
            onChange={() => onChange(choice.id)}
          />
          <span className="choice-card-icon" aria-hidden>
            {choice.icon}
          </span>
          <span className="choice-card-text">
            <span className="choice-card-title">
              <bdi>{choice.title}</bdi>
              {choice.note && (
                <span className="choice-card-note">{choice.note}</span>
              )}
            </span>
            {choice.help && (
              <span className="choice-card-help">{choice.help}</span>
            )}
          </span>
        </label>
      ))}
    </div>
  );
}
