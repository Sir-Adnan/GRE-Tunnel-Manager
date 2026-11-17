// Opening a form must not open the phone's keyboard: on touch-first devices
// nothing is focused automatically; a mouse or keyboard still starts in the
// first field. Screen readers keep their place: the dialog itself gets focus.

/** A device whose main pointer is a finger (phones, most tablets). */
export function touchFirst() {
  if (typeof window === "undefined" || !window.matchMedia) return false;
  return (
    window.matchMedia("(pointer: coarse)").matches &&
    !window.matchMedia("(pointer: fine)").matches
  );
}

/** For `autoFocus` on a field: only where it does not raise a keyboard. */
export const autoFocusField = () => !touchFirst();

/**
 * Radix `onOpenAutoFocus`: on touch-first devices focus the dialog container
 * (focusable, tabIndex -1) instead of its first field.
 */
export function quietOpenFocus(event: Event) {
  if (event.defaultPrevented || !touchFirst()) return;
  event.preventDefault();
  const container = event.currentTarget;
  if (container instanceof HTMLElement)
    container.focus({ preventScroll: true });
}
