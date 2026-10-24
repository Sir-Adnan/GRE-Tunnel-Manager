/** Copy only on an explicit user action; HTTP needs the legacy selection path. */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (typeof navigator.clipboard?.writeText === "function") {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // A denied modern API can still allow a user-initiated selection copy.
  }

  const active = document.activeElement as HTMLElement | null;
  const selection = document.getSelection();
  const ranges = selection
    ? Array.from({ length: selection.rangeCount }, (_, i) =>
        selection.getRangeAt(i).cloneRange(),
      )
    : [];
  const input =
    active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement
      ? active
      : null;
  const start = input?.selectionStart ?? null;
  const end = input?.selectionEnd ?? null;
  const direction = input?.selectionDirection ?? undefined;
  const field = document.createElement("textarea");
  field.value = text;
  field.readOnly = true;
  field.tabIndex = -1;
  field.dir = "ltr";
  // Keep focus inside Radix's modal trap and avoid layout/scroll changes.
  field.style.cssText =
    "position:fixed;inset:0 auto auto 0;width:1px;height:1px;padding:0;border:0;opacity:0;font-size:16px;pointer-events:none;";
  try {
    (
      active?.closest('[role="dialog"], [role="alertdialog"]') || document.body
    ).appendChild(field);
    field.focus({ preventScroll: true });
    field.select();
    field.setSelectionRange(0, text.length);
    return document.execCommand("copy") === true;
  } catch {
    return false;
  } finally {
    field.remove();
    active?.focus({ preventScroll: true });
    if (input && start !== null && end !== null) {
      input.setSelectionRange(start, end, direction);
    } else if (selection) {
      selection.removeAllRanges();
      for (const range of ranges) selection.addRange(range);
    }
  }
}
