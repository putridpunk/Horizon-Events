import { useState } from "react";
import usePolling from "../../services/usePolling.js";
import { getDesktopSettings, updateDesktopSettings } from "../../services/api.js";
import { ErrorBanner } from "../common.jsx";

/** Tray icon, notifications and starting with Windows. */
export default function DesktopCard() {
  const { data, error, reload } = usePolling(getDesktopSettings, [], 0);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);

  async function update(body) {
    setBusy(true);
    setMessage(null);
    try {
      await updateDesktopSettings(body);
      await reload();
    } catch (e) {
      setMessage(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  if (!data) return error ? <ErrorBanner error={error} /> : null;
  return (
    <section className="card">
      <h2>Running in the background</h2>
      {!data.enabled ? (
        <p className="muted">These settings are only available in the desktop app.</p>
      ) : (
        <>
          <p className="muted">
            Horizon Events shows an icon in the system tray. Closing the window can leave it running there so that it
            keeps watching and can tell you about new alerts. Choose <strong>Quit</strong> from the tray icon to stop it.
          </p>
          <div className="settings-form">
            <label className="check">
              <input type="checkbox" checked={data.run_in_background} disabled={busy}
                onChange={(e) => update({ run_in_background: e.target.checked })} />
              Keep running in the system tray when I close the window
            </label>
            <label>
              Show a Windows notification for new alerts
              <select value={data.notify} disabled={busy} onChange={(e) => update({ notify: e.target.value })}>
                <option value="critical">Critical alerts only</option>
                <option value="high">High and critical alerts</option>
                <option value="off">Never</option>
              </select>
            </label>
            <label className="check">
              <input type="checkbox" checked={data.start_with_windows} disabled={busy}
                onChange={(e) => update({ start_with_windows: e.target.checked })} />
              Start Horizon Events when I sign in to Windows (it opens in the tray)
            </label>
          </div>
        </>
      )}
      {message && <div className="error" role="alert">{message}</div>}
    </section>
  );
}
