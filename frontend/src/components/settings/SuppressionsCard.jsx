import { useState } from "react";
import usePolling from "../../services/usePolling.js";
import { deleteSuppression, listSuppressions } from "../../services/api.js";
import { EmptyState, ErrorBanner } from "../common.jsx";
import Time from "../ui/Time.jsx";

function describe(s) {
  const parts = [];
  if (s.rule_id) parts.push(`rule ${s.rule_id}`);
  if (s.source_ip) parts.push(`address ${s.source_ip}`);
  if (s.username) parts.push(`account ${s.username}`);
  return parts.join(", ");
}

/** The known false positives: alerts matching one of these are no longer raised. */
export default function SuppressionsCard() {
  const { data, error, reload } = usePolling(listSuppressions, [], 0);
  const [actionError, setActionError] = useState(null);

  async function remove(id) {
    setActionError(null);
    try {
      await deleteSuppression(id);
      await reload();
    } catch (e) {
      setActionError(e.message || String(e));
    }
  }

  const items = data?.items ?? [];
  return (
    <section className="card">
      <h2>Suppressed alerts</h2>
      <p className="muted">
        Detections that match one of these are not raised as alerts. Add one with <strong>Suppress similar alerts</strong>
        {" "}in an alert's detail panel, and remove it here to get those alerts back.
      </p>
      <ErrorBanner error={error} />
      {actionError && <div className="error" role="alert">{actionError}</div>}
      {data && items.length === 0 ? (
        <EmptyState>Nothing is suppressed.</EmptyState>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Matches</th><th>Note</th><th>Silenced</th><th>Added</th><th /></tr></thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id}>
                  <td>{describe(s)}</td>
                  <td>{s.note}</td>
                  <td>{s.hits}</td>
                  <td><Time value={s.created_at} /></td>
                  <td><button onClick={() => remove(s.id)} aria-label={`Remove suppression for ${describe(s)}`}>Remove</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
