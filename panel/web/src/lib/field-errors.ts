// Field errors shown under their fields. A form that validates on "Next" or
// "Save" provides the messages by input id; TextField and Choice read theirs,
// so a field never needs its own error plumbing.
import { createContext, useContext } from "react";
type Translate = (key: string) => string;

export const FieldErrorsContext = createContext<Record<string, string>>({});

/** The message for one field, or "" when it is fine. */
export function useFieldError(id?: string) {
  const errors = useContext(FieldErrorsContext);
  return (id && errors[id]) || "";
}

type Checked = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

/** A short, translated reason for a native validity failure. */
export function validityMessage(field: Checked, t: Translate) {
  const v = field.validity;
  if (v.customError) return field.validationMessage;
  if (v.valueMissing) return t("fieldRequired");
  if (v.rangeUnderflow || v.rangeOverflow) {
    const min = field.getAttribute("min"),
      max = field.getAttribute("max");
    if (min && max)
      return t("fieldRange").replace("{min}", min).replace("{max}", max);
  }
  if (v.tooLong)
    return t("fieldTooLong").replace(
      "{n}",
      field.getAttribute("maxlength") || "",
    );
  return t("fieldInvalid");
}

/** The visible name of a field, for the error summary. */
export function fieldName(field: Checked) {
  const label = field.id
    ? field.ownerDocument.querySelector(`label[for="${CSS.escape(field.id)}"]`)
    : null;
  return (
    label?.textContent?.trim() ||
    field.getAttribute("aria-label") ||
    field.name ||
    field.id
  );
}
