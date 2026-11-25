import { useState } from "react";
import usePolling from "../../services/usePolling.js";
import { backupData, cancelRestore, getDataStatus, purgeOldEvents, restoreData, setRetention } from "../../services/api.js";
import { hasFileDialogs, pickFile, pickSaveFile } from "../../services/desktop.js";
import { ErrorBanner } from "../common.jsx";
import Time from "../ui/Time.jsx";

const KEEP = [[0, "Keep everything"], [30, "30 days"], [90, "90 days"], [180, "6 months"], [365, "1 year"], [730, "2 years"]];

function megabytes(bytes) {
  return bytes == null ? "-" : `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Retention of old events, and backup and restore of the database. */
export default function DataCard() {
  const { data, error, reload } = usePolling(getDataStatus, [], 0);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);

  async function run(fn, okText) {
    setBusy(true);
    setMessage(null);
    try {
      const result = await fn();
      if (result !== null) setMessage({ ok: true, text: typeof okText === "function" ? okText(result) : okText });
      await reload();
    } catch (e) {
      setMessage({ ok: false, text: e.message || String(e) });
    } finally {
      setBusy(false);
    }
  }

  const backup = () => run(async () => {
    if (!hasFileDialogs()) throw new Error("Open Horizon Events from its desktop window to choose a file.");
    const stamp = new Date().toISOString().slice(0, 10);
    const path = await pickSaveFile(`horizon-events-${stamp}.hzbackup`);
    return path ? backupData(path) : null;
  }, (r) => `Backup saved to ${r.path}.`);

  const restore = () => run(async () => {
    if (!hasFileDialogs()) throw new Error("Open Horizon Events from its desktop window to choose a file.");
    const path = await pickFile();
    return path ? restoreData(path) : null;
  }, "The backup will replace your current data the next time Horizon Events starts. Close and reopen it to finish.");

  if (!data) return error ? <ErrorBanner error={error} /> : null;
  return (
    <section className="card">
      <h2>Data</h2>
      <p className="muted">
        {data.events.toLocaleString()} events stored
        {data.database_bytes != null && ` (${megabytes(data.database_bytes)})`}
        {data.oldest_event && <>, the oldest from <Time value={data.oldest_event} /></>}.
      </p>
      <div className="settings-form">
        <label>
          Delete old events after
          <select value={data.retention_days} disabled={busy}
            onChange={(e) => run(() => setRetention(Number(e.target.value)), "Saved.")}>
            {KEEP.map(([days, label]) => <option key={days} value={days}>{label}</option>)}
          </select>
        </label>
        <p className="muted">
          Events that belong to an alert are always kept, so the evidence behind your alerts is never removed.
        </p>
        <div className="actions">
          <button disabled={busy || data.retention_days === 0} onClick={() => run(purgeOldEvents, (r) => `Removed ${r.removed} old events.`)}>
            Clean up now
          </button>
        </div>
      </div>
      <h3>Backup</h3>
      {data.backups_available ? (
        <>
          <p className="muted">Save a copy of all your data, or replace your data with an earlier copy.</p>
          <div className="actions">
            <button className="primary" disabled={busy} onClick={backup}>Back up data…</button>
            <button disabled={busy} onClick={restore}>Restore from backup…</button>
          </div>
          {data.restore_pending && (
            <div className="mitigation" role="status">
              A restore is waiting for the next start of Horizon Events.
              <div className="actions">
                <button disabled={busy} onClick={() => run(cancelRestore, "The restore was cancelled.")}>Cancel the restore</button>
              </div>
            </div>
          )}
        </>
      ) : (
        <p className="muted">Backups are only available in the desktop app.</p>
      )}
      {message && <div className={message.ok ? "import-message" : "error"} role={message.ok ? "status" : "alert"}>{message.text}</div>}
    </section>
  );
}
