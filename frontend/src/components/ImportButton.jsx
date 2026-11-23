import { useRef, useState } from "react";
import { importLogs } from "../services/api.js";
import { SOURCES } from "../services/constants.js";

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
    <div>
      <div className="toolbar" style={{ marginBottom: 6, justifyContent: "flex-end" }}>
        <select value={sourceType} onChange={(e) => setSourceType(e.target.value)} aria-label="Log source type">
          {SOURCES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <button className="primary" disabled={busy} onClick={() => fileRef.current?.click()}>
          {busy ? "Importing…" : "Import logs"}
        </button>
        <input ref={fileRef} type="file" hidden onChange={onFile} />
      </div>
      {status && <div className={status.ok ? "muted" : "error"} style={{ textAlign: "right" }}>{status.text}</div>}
    </div>
  );
}
