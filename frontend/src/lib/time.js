const HAS_ZONE = /(Z|[+-]\d\d:?\d\d)$/i;

/** Parse an API timestamp. The backend stores naive UTC, so a stamp without a timezone is read as UTC
 *  (not as local time, which is what `new Date(...)` would do). Returns null if it is not a date. */
export function parseTimestamp(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  const text = value.trim();
  const date = new Date(HAS_ZONE.test(text) ? text : `${text}Z`);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** Human-friendly age: "just now", "12 min ago", "3 h ago", "2 d ago", then a plain date from 7 days.
 *  `exact` is the full local timestamp, meant for a hover tooltip. */
export function formatRelative(value, now = Date.now()) {
  const date = parseTimestamp(value);
  if (!date) return { text: "-", exact: "" };
  const seconds = Math.max(0, Math.floor((now - date.getTime()) / 1000));
  let text;
  if (seconds < 60) text = "just now";
  else if (seconds < 3600) text = `${Math.floor(seconds / 60)} min ago`;
  else if (seconds < 86400) text = `${Math.floor(seconds / 3600)} h ago`;
  else if (seconds < 7 * 86400) text = `${Math.floor(seconds / 86400)} d ago`;
  else text = date.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
  return { text, exact: date.toLocaleString() };
}
