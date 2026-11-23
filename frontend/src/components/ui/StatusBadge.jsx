import Icon from "./Icon.jsx";

const STATUS = {
  OPEN: ["Open", "bell"],
  INVESTIGATING: ["Investigating", "search"],
  RESOLVED: ["Resolved", "check"],
};

export default function StatusBadge({ value }) {
  const entry = STATUS[value];
  if (!entry) return <span className="badge">{value}</span>;
  return (
    <span className={`badge ${value}`}>
      <Icon name={entry[1]} size={14} />
      {entry[0]}
    </span>
  );
}
