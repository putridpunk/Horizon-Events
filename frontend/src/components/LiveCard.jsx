import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { getWatcherStatus, pauseWatcher, resumeWatcher } from "../services/api.js";
import { fmtTime } from "../services/constants.js";
import { ErrorBanner } from "./common.jsx";

export default function LiveCard() {
  const { data, error, reload } = usePolling(getWatcherStatus, [], 3000);
  const [busy, setBusy] = useState(false);

  async function toggle() {
    setBusy(true);
    try {
      await (data.paused ? resumeWatcher() : pauseWatcher());
      await reload();
    } finally {
      setBusy(false);
    }
  }

  const state = !data ? "Loading" : !data.enabled ? "Not configured" : data.paused ? "Paused" : "Live";
  return (
    <section className="card" style={{ marginTop: 16 }}>
      <div className="topbar" style={{ marginBottom: 8 }}>
        <h2>
          Live monitoring <span className={`badge ${state === "Live" ? "RESOLVED" : "INVESTIGATING"}`}>{state}</span>
        </h2>
        {data?.enabled && (
          <button disabled={busy} onClick={toggle}>{data.paused ? "Resume" : "Pause"}</button>
        )}
      </div>
      <ErrorBanner error={error} />
      {data && !data.enabled && (
        <p className="muted">Set HORIZON_WATCH_DIR to ingest log files continuously from a watch folder.</p>
      )}
      {data?.enabled && (
        <>
          <p className="muted mono">{data.directory} · subfolder = source type · polling every {data.interval}s</p>
          {data.files.length ? (
            <div className="table-wrap">
              <table>
                <thead><tr><th>File</th><th>Lines</th><th>Imported</th><th>Skipped</th><th>Alerts</th><th>Last activity</th></tr></thead>
                <tbody>
                  {data.files.map((f) => (
                    <tr key={f.path}>
                      <td className="mono">{f.path}{f.last_error && <div className="error">{f.last_error}</div>}</td>
                      <td>{f.lines}</td><td>{f.imported}</td><td>{f.skipped}</td><td>{f.alerts}</td>
                      <td className="muted">{fmtTime(f.last_activity)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="muted">No files yet. Append log lines to a file such as linux_auth/auth.log in the watch folder.</p>
          )}
        </>
      )}
    </section>
  );
}
