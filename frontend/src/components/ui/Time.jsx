import { formatRelative } from "../../lib/time.js";

/** A timestamp shown as its age ("12 min ago"); the exact local time is the tooltip. */
export default function Time({ value, now }) {
  const { text, exact } = formatRelative(value, now);
  if (!exact) return <span className="muted">{text}</span>;
  return <time dateTime={value} title={exact}>{text}</time>;
}
