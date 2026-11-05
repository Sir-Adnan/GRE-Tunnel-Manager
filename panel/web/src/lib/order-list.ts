// Framework-free list ordering (unit-tested in tests/forwarding.test.mjs).

/** Sorts items by a saved order; unknown items keep their place after known ones. */
export function applyOrder<T>(items: readonly T[], ids: readonly string[] | undefined, key: (item: T) => string) {
  if (!ids?.length) return [...items];
  const rank = new Map(ids.map((id, i) => [id, i]));
  return items
    .map((item, index) => ({ item, index, r: rank.get(key(item)) }))
    .sort((a, b) => {
      if (a.r !== undefined && b.r !== undefined) return a.r - b.r;
      if (a.r !== undefined) return -1;
      if (b.r !== undefined) return 1;
      return a.index - b.index;
    })
    .map((x) => x.item);
}

/**
 * Moves `moved` (a visible subset, already reordered) back into the full
 * order: the visible items take the positions they held, in their new order.
 */
export function mergeOrder(full: readonly string[], visibleBefore: readonly string[], visibleAfter: readonly string[]) {
  const slots = new Set(visibleBefore);
  const queue = [...visibleAfter];
  return full.map((id) => (slots.has(id) ? (queue.shift() ?? id) : id));
}
