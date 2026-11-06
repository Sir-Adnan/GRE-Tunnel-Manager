/** Keep old section bookmarks working while tabs use browser history. */
export function settingsTab(params: URLSearchParams): string {
  const tab = params.get("tab");
  if (
    tab &&
    ["security", "appearance", "notifications", "metrics"].includes(tab)
  )
    return tab;
  const section = params.get("section");
  if (section === "notifications" || section === "metrics") return section;
  return "security";
}
