import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { getAlert, suppressAlert, updateAlert } from "../services/api.js";
import { fmtTime } from "../services/constants.js";
import { ErrorBanner, SeverityBadge, StatusBadge } from "./common.jsx";
import TechniqueBadges from "./TechniqueBadges.jsx";
import IntelBadge from "./IntelBadge.jsx";
import { Drawer } from "./overlay.jsx";
import MitigationPanel from "./MitigationPanel.jsx";
import TriagePanel from "./TriagePanel.jsx";

const NEXT = {
  OPEN: [["INVESTIGATING", "Start investigation"], ["RESOLVED", "Resolve"]],
  INVESTIGATING: [["RESOLVED", "Resolve"], ["OPEN", "Reopen"]],
  RESOLVED: [["OPEN", "Reopen"]],
};

export default function AlertDrawer({ alertId, onClose, onChanged }) {
  const { data: alert, error, reload } = usePolling(() => getAlert(alertId), [alertId]);
  const [note, setNote] = useState("");
  const [actionError, setActionError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [confirmSuppress, setConfirmSuppress] = useState(false);

  async function change(status) {
    setBusy(true);
    setActionError(null);
    try {
      await updateAlert(alertId, { status, note: note.trim() || null });
      setNote("");
      await reload();
      onChanged?.();
    } catch (e) {
      setActionError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function suppress() {
    setBusy(true);
    setActionError(null);
    try {
      await suppressAlert(alertId);
      setConfirmSuppress(false);
      await reload();
      onChanged?.();
    } catch (e) {
      setActionError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Drawer title={alert ? alert.alert_id : "Alert"} subtitle={alert ? `${alert.rule_id} · ${alert.rule_name}` : null}
      onClose={onClose}>
        <ErrorBanner error={error} />
        {alert && (
          <>
            <p>
              <SeverityBadge value={alert.severity} /> <StatusBadge value={alert.status} />
            </p>
            <p>{alert.description}</p>
            {alert.techniques?.length > 0 && (
              <>
                <h2>MITRE ATT&amp;CK</h2>
                <TechniqueBadges techniques={alert.techniques} />
              </>
            )}
            {alert.iocs?.length > 0 && (
              <div className="mitigation" role="group" aria-label="Threat list matches">
                <strong>On a threat list you imported</strong>
                <ul>
                  {alert.iocs.map((i) => (
                    <li key={`${i.kind}-${i.value}`}><span className="mono">{i.value}</span> ({i.kind}) · {i.feed}</li>
                  ))}
                </ul>
              </div>
            )}
            <p className="muted">
              This alert flags suspicious activity for investigation. It is not a confirmed breach.
            </p>
            <dl className="kv">
              <dt>Source IP</dt><dd className="mono">{alert.source_ip || "-"}<IntelBadge intel={alert.intel} /></dd>
              <dt>Target account</dt><dd>{alert.username || "-"}</dd>
              <dt>Occurrences</dt><dd>{alert.occurrences}</dd>
              <dt>Detection window</dt><dd>{alert.window_minutes ? `${alert.window_minutes} minutes` : "-"}</dd>
              <dt>Last activity</dt><dd>{fmtTime(alert.last_seen)}</dd>
              <dt>Created</dt><dd>{fmtTime(alert.created_at)}</dd>
            </dl>

            <MitigationPanel alertId={alertId} />

            <TriagePanel alert={alert} onSaved={async () => { await reload(); onChanged?.(); }} />

            <h2>Investigation</h2>
            <textarea
              rows={2}
              style={{ width: "100%" }}
              placeholder="Add a note (optional)"
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
            <div className="actions">
              {NEXT[alert.status].map(([status, label]) => (
                <button key={status} className={status === "INVESTIGATING" ? "primary" : ""} disabled={busy}
                  onClick={() => change(status)}>
                  {label}
                </button>
              ))}
            </div>
            {actionError && <div className="error">{actionError}</div>}
            {alert.rule_id !== "HZ-008" && (confirmSuppress ? (
              <div className="mitigation" role="group" aria-label="Confirm suppression">
                <p>
                  Future alerts from {alert.rule_id}
                  {alert.source_ip ? ` for ${alert.source_ip}` : ""}{alert.username ? ` and account ${alert.username}` : ""} will
                  not be raised, and this alert will be resolved. You can undo this in Settings.
                </p>
                <div className="actions">
                  <button className="primary" disabled={busy} onClick={suppress}>Suppress and resolve</button>
                  <button disabled={busy} onClick={() => setConfirmSuppress(false)}>Cancel</button>
                </div>
              </div>
            ) : (
              <p><button disabled={busy} onClick={() => setConfirmSuppress(true)}>Suppress similar alerts…</button></p>
            ))}

            <h2>History</h2>
            <ul className="timeline">
              {alert.history.map((h, i) => (
                <li key={i}>
                  <div>
                    {h.from_status ? `${h.from_status} → ${h.to_status}` : `Created as ${h.to_status}`}
                  </div>
                  <div className="muted">{fmtTime(h.at)}{h.note ? ` · ${h.note}` : ""}</div>
                </li>
              ))}
            </ul>

            <h2>Related events ({alert.events.length})</h2>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Time</th><th>Type</th><th>User</th><th>IP</th></tr></thead>
                <tbody>
                  {alert.events.map((e) => (
                    <tr key={e.id}>
                      <td className="mono">{fmtTime(e.timestamp)}</td>
                      <td>{e.event_type}</td>
                      <td>{e.username || "-"}</td>
                      <td className="mono">{e.source_ip || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
    </Drawer>
  );
}
