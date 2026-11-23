import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { addIncidentNote, getIncident, mergeIncident, removeIncidentAlert, updateIncident } from "../services/api.js";
import { fmtTime } from "../services/constants.js";
import { ErrorBanner, SeverityBadge, StatusBadge } from "./common.jsx";
import IntelBadge from "./IntelBadge.jsx";
import TechniqueBadges from "./TechniqueBadges.jsx";
import { Drawer } from "./overlay.jsx";

const NEXT = {
  OPEN: [["INVESTIGATING", "Start investigation"], ["RESOLVED", "Resolve"]],
  INVESTIGATING: [["RESOLVED", "Resolve"], ["OPEN", "Reopen"]],
  RESOLVED: [["OPEN", "Reopen"]],
};

const ACTION_LABELS = {
  created: "Opened", alert_added: "Alert added", alert_removed: "Alert removed", status_changed: "Status changed",
  note: "Note", merged: "Merged", title_changed: "Renamed",
};

export default function IncidentDrawer({ incidentId, others, onClose, onChanged }) {
  const { data: inc, error, reload } = usePolling(() => getIncident(incidentId), [incidentId]);
  const [note, setNote] = useState("");
  const [title, setTitle] = useState("");
  const [mergeInto, setMergeInto] = useState("");
  const [actionError, setActionError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function run(fn) {
    setBusy(true);
    setActionError(null);
    try {
      await fn();
      await reload();
      onChanged?.();
    } catch (e) {
      setActionError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const changeStatus = (status) => run(async () => {
    await updateIncident(incidentId, { status, note: note.trim() || null });
    setNote("");
  });
  const addNote = () => run(async () => { await addIncidentNote(incidentId, note); setNote(""); });
  const rename = () => run(async () => { await updateIncident(incidentId, { title }); setTitle(""); });
  const merge = () => run(async () => { await mergeIncident(incidentId, Number(mergeInto)); setMergeInto(""); });

  return (
    <Drawer title={inc ? inc.incident_id : "Incident"} subtitle={inc ? inc.title : null} onClose={onClose}>
        <ErrorBanner error={error} />
        {inc && (
          <>
            <p><SeverityBadge value={inc.severity} /> <StatusBadge value={inc.status} /></p>
            <p className="muted">
              A group of related alerts to investigate together. It does not mean a breach is confirmed.
            </p>
            <dl className="kv">
              <dt>Source IPs</dt><dd className="mono">{inc.ips.join(", ") || "-"}</dd>
              <dt>Accounts</dt><dd>{inc.accounts.join(", ") || "-"}</dd>
              <dt>First activity</dt><dd>{fmtTime(inc.first_activity)}</dd>
              <dt>Last activity</dt><dd>{fmtTime(inc.last_activity)}</dd>
              <dt>Alerts</dt><dd>{inc.alert_count}</dd>
            </dl>
            {inc.techniques.length > 0 && (
              <>
                <h2>MITRE ATT&amp;CK</h2>
                <TechniqueBadges techniques={inc.techniques} />
              </>
            )}

            <h2>Investigation</h2>
            <textarea rows={2} style={{ width: "100%" }} placeholder="Add a note (optional for status changes)"
              value={note} onChange={(e) => setNote(e.target.value)} />
            <div className="actions">
              {NEXT[inc.status].map(([status, label]) => (
                <button key={status} className={status === "INVESTIGATING" ? "primary" : ""} disabled={busy}
                  onClick={() => changeStatus(status)}>{label}</button>
              ))}
              <button disabled={busy || !note.trim()} onClick={addNote}>Add note only</button>
            </div>
            <div className="toolbar">
              <input placeholder="Rename incident" value={title} onChange={(e) => setTitle(e.target.value)} />
              <button disabled={busy || !title.trim()} onClick={rename}>Rename</button>
            </div>
            {others.length > 0 && inc.status !== "RESOLVED" && (
              <div className="toolbar">
                <select value={mergeInto} onChange={(e) => setMergeInto(e.target.value)}>
                  <option value="">Merge into…</option>
                  {others.map((o) => <option key={o.id} value={o.id}>{o.incident_id} · {o.title}</option>)}
                </select>
                <button disabled={busy || !mergeInto} onClick={merge}>Merge</button>
              </div>
            )}
            {actionError && <div className="error">{actionError}</div>}

            <h2>Alerts ({inc.alerts.length})</h2>
            <div className="table-wrap">
              <table>
                <tbody>
                  {inc.alerts.map((a) => (
                    <tr key={a.id}>
                      <td><SeverityBadge value={a.severity} /></td>
                      <td>
                        {a.rule_name} <span className="muted mono">{a.alert_id}</span>
                        <div className="muted mono">{a.source_ip || a.username || ""}<IntelBadge intel={a.intel} /></div>
                      </td>
                      <td><StatusBadge value={a.status} /></td>
                      <td>
                        <button disabled={busy} title="Remove from this incident"
                          onClick={() => run(() => removeIncidentAlert(incidentId, a.id))}>Remove</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <h2>Audit trail</h2>
            <ul className="timeline">
              {inc.history.map((h, i) => (
                <li key={i}>
                  <div>
                    {ACTION_LABELS[h.action] || h.action}
                    {h.from_status ? `: ${h.from_status} → ${h.to_status}` : ""}
                  </div>
                  <div className="muted">{fmtTime(h.at)}{h.detail ? ` · ${h.detail}` : ""}</div>
                </li>
              ))}
            </ul>
          </>
        )}
    </Drawer>
  );
}
