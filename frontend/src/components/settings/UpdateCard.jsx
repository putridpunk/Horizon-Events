import { useState } from "react";
import usePolling from "../../services/usePolling.js";
import { checkForUpdate, getUpdateStatus, setAutoUpdateCheck } from "../../services/api.js";
import { ErrorBanner } from "../common.jsx";
import Time from "../ui/Time.jsx";

/** Is there a newer release? It only tells you; nothing is downloaded or installed. */
export default function UpdateCard() {
  const { data, error, reload } = usePolling(getUpdateStatus, [], 0);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const [shown, setShown] = useState(null);
  const s = shown ?? data;

  async function run(action) {
    setBusy(true);
    setMessage(null);
    try {
      setShown(await action());
      await reload();
    } catch (e) {
      setMessage(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  if (!s) return error ? <ErrorBanner error={error} /> : null;
  return (
    <section className="card">
      <h2>Updates</h2>
      <p>{`You have version ${s.current}.`}</p>
      {s.update_available ? (
        <div className="mitigation" role="group" aria-label="Update available">
          <strong>{`Version ${s.latest} is available.`}</strong>
          {s.notes && <p>{s.notes.length > 400 ? `${s.notes.slice(0, 400)}…` : s.notes}</p>}
          <p>
            <a href={s.url} target="_blank" rel="noopener noreferrer">See what changed and download it</a>
            <span className="muted"> (opens the release page; Horizon Events does not install anything by itself)</span>
          </p>
        </div>
      ) : s.checked_at && !s.error ? (
        <p className="muted">This is the latest version. Last checked: <Time value={s.checked_at} /></p>
      ) : null}
      {s.error && <div className="error" role="alert">{s.error}</div>}
      {message && <div className="error" role="alert">{message}</div>}
      <p className="muted">
        Checking asks GitHub for the newest release number. It sends no information about you or your data, but GitHub can see
        this computer's internet address, so it only happens when you ask, or every day if you switch it on below.
      </p>
      <div className="actions">
        <button disabled={busy} onClick={() => run(checkForUpdate)}>Check for updates now</button>
      </div>
      <label className="check">
        <input type="checkbox" checked={s.auto_check} disabled={busy} onChange={(e) => run(() => setAutoUpdateCheck(e.target.checked))} />
        <span>Check for updates automatically once a day</span>
      </label>
    </section>
  );
}
