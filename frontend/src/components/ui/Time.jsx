import { formatRelative, parseTimestamp } from "../../lib/time.js";

/** A timestamp shown as its age ("12 min ago"); the exact local time is the tooltip.
 *  With `upcoming`, a time clearly in the future is shown as a full local date and time instead. */
export default function Time({ value, now, upcoming }) {
  const { text, exact } = formatRelative(value, now);
  if (!exact) return <span className="muted">{text}</span>;
  const date = parseTimestamp(value);
  if (upcoming && date && date.getTime() - (now ?? Date.now()) > 60000) {
    return <time dateTime={value} title={exact}>{exact}</time>;
  }
  return <time dateTime={value} title={exact}>{text}</time>;
}
