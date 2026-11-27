import { useEffect, useState } from "react";
import { triageAlert } from "../services/api.js";

function lateText(minutes) {
  if (minutes < 60) return `${minutes} min`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)} h`;
  return `${Math.floor(minutes / 1440)} d`;
}

/** Who is working on an alert, its labels, and whether it has waited longer than its severity allows. */
export default function TriagePanel({ alert, onSaved }) {
  const [assignee, setAssignee] = useState(alert.assignee ?? "");
  const [tags, setTags] = useState((alert.tags ?? []).join(", "));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    setAssignee(alert.assignee ?? "");
    setTags((alert.tags ?? []).join(", "));
  }, [alert.assignee, alert.tags]);

  async function save(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await triageAlert(alert.id, {
        assignee: assignee.trim() || null,
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
      });
      await onSaved?.();
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h2>Owner and tags</h2>
      <p className="muted">
        Waiting {lateText(alert.age_minutes ?? 0)}; target for {alert.severity} alerts is {lateText(alert.sla_minutes ?? 0)}.
        {alert.sla_breached && <strong className="sla-late"> This alert is late.</strong>}
      </p>
      <form className="settings-form" onSubmit={save}>
        <label>
          Owner
          <input value={assignee} maxLength={100} placeholder="Who is working on this (optional)"
            onChange={(e) => setAssignee(e.target.value)} />
        </label>
        <label>
          Tags
          <input value={tags} placeholder="Separate with commas, for example: phishing, vip"
            onChange={(e) => setTags(e.target.value)} />
        </label>
        <div className="actions">
          <button type="submit" disabled={busy}>Save owner and tags</button>
        </div>
        {error && <div className="error" role="alert">{error}</div>}
      </form>
    </>
  );
}
