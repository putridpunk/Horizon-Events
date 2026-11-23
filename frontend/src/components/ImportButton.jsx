import { useRef, useState } from "react";
import { importLogs } from "../services/api.js";
import { SOURCES } from "../services/constants.js";
import Icon from "./ui/Icon.jsx";

const SOURCE_LABELS = {
  linux_auth: "Linux auth log", linux_syslog: "Linux syslog", windows: "Windows events",
  application: "Application log", json: "JSON lines",
};

/** Import a log file you already have. Lives in the top bar, so it is available on every page. */
export default function ImportButton({ onDone }) {
  const [sourceType, setSourceType] = useState(SOURCES[0]);
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(false);
  const fileRef = useRef(null);

  async function onFile(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true);
    setStatus(null);
    try {
      const r = await importLogs(file, sourceType);
      setStatus({ ok: true, text: `${r.imported} imported, ${r.skipped} skipped, ${r.duplicates} duplicates, ${r.alerts_created} new alerts` });
      onDone?.();
    } catch (err) {
      setStatus({ ok: false, text: err.message });
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  return (
    <div className="import">
      <select value={sourceType} onChange={(e) => setSourceType(e.target.value)} aria-label="Log source type">
        {SOURCES.map((s) => <option key={s} value={s}>{SOURCE_LABELS[s] ?? s}</option>)}
      </select>
      <button className="primary" disabled={busy} onClick={() => fileRef.current?.click()}>
        <Icon name="upload" />
        {busy ? "Importing…" : "Import logs"}
      </button>
      <input ref={fileRef} type="file" hidden onChange={onFile} data-testid="import-file" />
      {status && (
        <div className={`import-message ${status.ok ? "" : "error"}`} role="status">
          <span>{status.text}</span>
          <button className="icon-button" aria-label="Dismiss" onClick={() => setStatus(null)}><Icon name="close" size={14} /></button>
        </div>
      )}
    </div>
  );
}
