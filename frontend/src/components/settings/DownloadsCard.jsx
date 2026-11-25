import { useState } from "react";
import usePolling from "../../services/usePolling.js";
import { getDownloadsScan, updateDownloadsScan } from "../../services/api.js";
import { hasPicker, pickFolder } from "../../services/desktop.js";
import { ErrorBanner } from "../common.jsx";

/** Scan files as they arrive in the Downloads folder. Off by default. */
export default function DownloadsCard() {
  const { data, error, reload } = usePolling(getDownloadsScan, [], 5000);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);

  async function update(body) {
    setBusy(true);
    setMessage(null);
    try {
      await updateDownloadsScan(body);
      await reload();
    } catch (e) {
      setMessage(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  async function chooseFolder() {
    if (!hasPicker()) {
      setMessage("Open Horizon Events from its desktop window to choose a folder.");
      return;
    }
    const [path] = await pickFolder();
    if (path) await update({ folder: path });
  }

  if (!data) return error ? <ErrorBanner error={error} /> : null;
  return (
    <section className="card">
      <h2>Scan new downloads</h2>
      {!data.available ? (
        <p className="muted">Scanning downloads is only available in the desktop app.</p>
      ) : (
        <>
          <p className="muted">
            Each new file that lands in the folder is scanned with Microsoft Defender once it has finished downloading.
            Files that are already there are not scanned. Anything found becomes an alert.
          </p>
          <div className="settings-form">
            <label className="check">
              <input type="checkbox" checked={data.enabled} disabled={busy}
                onChange={(e) => update({ enabled: e.target.checked })} />
              Scan new files in this folder automatically
            </label>
            <div>
              <div><strong>Folder:</strong> <span className="path">{data.effective_folder}</span></div>
              <div className="actions">
                <button disabled={busy} onClick={chooseFolder}>Choose another folder…</button>
                {data.folder && <button disabled={busy} onClick={() => update({ folder: "" })}>Use the Downloads folder</button>}
              </div>
            </div>
            {data.enabled && (
              <p className="muted" role="status">
                {data.watching ? `Watching. ${data.scanned} scanned so far, ${data.queued} waiting.` : "Starting to watch…"}
              </p>
            )}
          </div>
        </>
      )}
      {message && <div className="error" role="alert">{message}</div>}
    </section>
  );
}
