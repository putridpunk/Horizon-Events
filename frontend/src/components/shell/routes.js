// The pages of the app, grouped the way the sidebar shows them: [path, label, icon].
export const NAV_GROUPS = [
  ["Monitor", [["/", "Overview", "dashboard"], ["/events", "Events", "list"], ["/sources", "Data sources", "database"]]],
  ["Respond", [["/alerts", "Alerts", "bell"], ["/incidents", "Incidents", "folders"], ["/scan", "Scan files", "shield"], ["/mitigation", "Mitigation", "lock"]]],
  ["Insight", [["/analytics", "Analytics", "chart"], ["/reports", "Reports", "file"]]],
];

/** Breadcrumb parts for a path: { group, title }. Unknown paths fall back to the app name. */
export function locate(pathname) {
  for (const [group, links] of NAV_GROUPS) {
    const hit = links.find(([path]) => (path === "/" ? pathname === "/" : pathname === path || pathname.startsWith(`${path}/`)));
    if (hit) return { group, title: hit[1] };
  }
  if (pathname === "/setup") return { group: "Monitor", title: "Setup" };
  return { group: null, title: "Horizon Events" };
}
