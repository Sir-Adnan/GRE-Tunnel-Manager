// Styles the panel offers, in the pack's curated order (default first) rather than alphabetically.
import { styleGallery } from "./gallery";
import { registry } from "./registry.generated";

const packId = "tunnel-admin";

export function styleChoices(locale: string, current?: string) {
  const order = registry.packs[packId].compatibleStyleIds;
  return styleGallery(registry, { surface: "admin", packId, locale, current })
    .flatMap((group) => group.items)
    .sort((a, b) => order.indexOf(a.id) - order.indexOf(b.id));
}
