// What the Overview page shows and in which order, kept in this browser only (nothing is sent to the server).
export const STORAGE_KEY = "horizon.dashboard";

export const WIDGETS = [
  { id: "stats", title: "Key numbers" },
  { id: "attention", title: "Needs attention" },
  { id: "timeline", title: "Events over time" },
  { id: "types", title: "Most frequent event types" },
  { id: "ips", title: "Most common source IPs" },
  { id: "severity", title: "Alert severity" },
];

// [id, label, hours]: the time range of the "Events over time" chart.
export const RANGES = [["24h", "Last 24 hours", 24], ["7d", "Last 7 days", 168], ["30d", "Last 30 days", 720], ["all", "All time", null]];

export const DEFAULT_PREFS = {
  order: WIDGETS.map((w) => w.id),
  hidden: ["types", "ips", "severity"],
  range: "all",
};

const IDS = new Set(WIDGETS.map((w) => w.id));

/** Whatever is stored is cleaned up: unknown widgets dropped, new widgets added at the end, a bad range ignored. */
export function sanitize(value) {
  const v = value && typeof value === "object" ? value : {};
  const order = [...new Set(Array.isArray(v.order) ? v.order.filter((id) => IDS.has(id)) : [])];
  for (const id of DEFAULT_PREFS.order) if (!order.includes(id)) order.push(id);
  const hidden = Array.isArray(v.hidden) ? [...new Set(v.hidden.filter((id) => IDS.has(id)))] : [...DEFAULT_PREFS.hidden];
  const range = RANGES.some(([id]) => id === v.range) ? v.range : DEFAULT_PREFS.range;
  return { order, hidden, range };
}

export function loadPrefs(storage = globalThis.localStorage) {
  try {
    return sanitize(JSON.parse(storage?.getItem(STORAGE_KEY) ?? "null"));
  } catch {
    return sanitize(null);
  }
}

export function savePrefs(prefs, storage = globalThis.localStorage) {
  try {
    storage?.setItem(STORAGE_KEY, JSON.stringify(sanitize(prefs)));
  } catch {
    /* private mode or a full store: the choice just lasts until the page is closed */
  }
}

export const rangeStart = (range, now = Date.now()) => {
  const hours = RANGES.find(([id]) => id === range)?.[2];
  return hours ? new Date(now - hours * 3_600_000).toISOString().slice(0, 19) : undefined;
};

export const rangeBucket = (range) => (range === "30d" ? "day" : "hour");
