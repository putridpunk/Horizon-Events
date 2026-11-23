/** What this place shows, and what to do next. `title` and `action` are optional; with nothing at all it
 *  says "Nothing to show yet." */
export default function EmptyState({ title, children, action }) {
  const body = children ?? (title ? null : "Nothing to show yet.");
  return (
    <div className="empty">
      {title && <strong>{title}</strong>}
      {body && <div>{body}</div>}
      {action && <div style={{ marginTop: 12 }}>{action}</div>}
    </div>
  );
}
