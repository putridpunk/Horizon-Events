import Icon from "./Icon.jsx";

const SEVERITY = {
  critical: ["Critical", "alert"],
  high: ["High", "arrow-up"],
  medium: ["Medium", "minus"],
  low: ["Low", "arrow-down"],
};

/** Severity as an icon plus a word: never colour alone. */
export default function SeverityBadge({ value }) {
  const entry = SEVERITY[value];
  if (!entry) return <span className="badge">{value}</span>;
  return (
    <span className={`badge ${value}`}>
      <Icon name={entry[1]} size={14} />
      {entry[0]}
    </span>
  );
}
