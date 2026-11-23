import { fmtTime } from "../services/constants.js";
import EnableAccess from "./EnableAccess.jsx";

export const STATE_LABELS = {
  off: "Off",
  collecting: "Collecting",
  needs_permission: "Needs permission",
  waiting_signout: "Waiting for sign-out",
  unavailable: "Unavailable",
};
const STATE_CLASS = {
  collecting: "RESOLVED", needs_permission: "INVESTIGATING", waiting_signout: "INVESTIGATING",
  off: "low", unavailable: "low",
};

/** One log source: a switch, what it reads, its state, and what to do about it. */
export default function SourceRow({ item, checked, onToggle, onCheck, onAccessRequested, showDetails = false, busy = false }) {
  // A blocked source says why, whether or not it has been switched on yet; otherwise show its own state.
  const shown = item.access !== "ready" ? item.access : item.state;
  const label = STATE_LABELS[shown] ?? shown;
  const needsPermission = item.access === "needs_permission";
  return (
    <div className="source-row">
      <label className="source-main">
        <input type="checkbox" checked={checked} disabled={busy || item.access === "unavailable"}
          aria-label={`Collect ${item.name}`} onChange={(e) => onToggle?.(e.target.checked)} />
        <span>
          <strong>{item.name}</strong>
          <span className="muted source-desc">{item.description}</span>
        </span>
      </label>
      <div className="source-state">
        <span className={`badge ${STATE_CLASS[shown] ?? "low"}`}>{label}</span>
        {showDetails && (
          <div className="muted">
            {item.events_read} events read · last event {item.last_activity ? fmtTime(item.last_activity) : "none yet"}
          </div>
        )}
      </div>
      <div className="source-actions">
        {needsPermission && item.platform === "windows" && <EnableAccess onRequested={onAccessRequested} />}
        {item.access === "waiting_signout" && (
          <p className="muted">
            Permission granted. Sign out of Windows and back in once; collection then starts by itself.
          </p>
        )}
        {item.access === "unavailable" && <p className="muted">This log is not available on this computer.</p>}
        {onCheck && <button disabled={busy} onClick={onCheck}>Check access</button>}
      </div>
      {item.last_error && <div className="error source-error">{item.last_error}</div>}
    </div>
  );
}
