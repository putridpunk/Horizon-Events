export function StatCard({ label, value, tone = "" }) {
  return (
    <div className={`card stat ${tone}`}>
      <div className="label">{label}</div>
      <div className="value">{value ?? "-"}</div>
    </div>
  );
}

export { default as SeverityBadge } from "./ui/SeverityBadge.jsx";
export { default as StatusBadge } from "./ui/StatusBadge.jsx";
export { default as EmptyState } from "./ui/EmptyState.jsx";

export function ErrorBanner({ error }) {
  return error ? <div className="error">Could not load data: {error}</div> : null;
}

export function PageHeader({ title, subtitle, children }) {
  return (
    <div className="topbar">
      <div>
        <h1>{title}</h1>
        {subtitle && <p>{subtitle}</p>}
      </div>
      <div>{children}</div>
    </div>
  );
}

export function Pager({ offset, limit, total, onChange }) {
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  return (
    <div className="pager">
      <span>
        Page {page} of {pages} · {total} total
      </span>
      <button disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>
        Prev
      </button>
      <button disabled={page >= pages} onClick={() => onChange(offset + limit)}>
        Next
      </button>
    </div>
  );
}
