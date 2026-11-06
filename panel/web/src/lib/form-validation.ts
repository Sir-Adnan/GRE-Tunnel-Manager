/** Reveal the field's containing disclosure and controlled advanced tab before
 * asking the browser to focus it. Inactive Radix panels remain mounted. */
export function revealInvalidField(
  invalid: HTMLInputElement,
  activateTab: (section: string) => void,
) {
  let disclosure = invalid.closest("details");
  while (disclosure) {
    disclosure.open = true;
    disclosure = disclosure.parentElement?.closest("details") ?? null;
  }
  const section = invalid.closest<HTMLElement>("[data-advanced-section]")
    ?.dataset.advancedSection;
  if (section) activateTab(section);
  invalid.setAttribute("aria-invalid", "true");
  invalid.closest("[data-slot=field]")?.setAttribute("data-invalid", "true");
  requestAnimationFrame(() => {
    invalid.scrollIntoView({ block: "nearest" });
    invalid.focus({ preventScroll: true });
    invalid.reportValidity();
  });
}
