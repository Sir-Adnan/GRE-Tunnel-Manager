/** Case-insensitive match of every typed word, so "hap new" finds "New HAProxy connection". */
export function matchCommands<
  T extends { label: string; keywords?: string; group: string },
>(commands: readonly T[], query: string): T[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  return commands.filter((command) => {
    const text =
      `${command.label} ${command.keywords || ""} ${command.group}`.toLowerCase();
    return words.every((word) => text.includes(word));
  });
}
