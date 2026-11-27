import { useState } from "react";
import { importSigmaRule } from "../../services/api.js";

/** Paste a Sigma rule (YAML). It is checked first and only the parts Horizon Events can evaluate are accepted. */
export default function SigmaImport({ onSaved, onClose }) {
  const [text, setText] = useState("");
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function run(action) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (e) {
      setPreview(null);
      setError(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="settings-form">
      <p className="muted">
        Sigma is a common format for sharing detections. Searches over fields (with contains, startswith, endswith, all and
        cidr), keywords, and conditions using and, or, not and "1 of" are supported. Regular expressions, encodings and counts
        over time are not, and the rule is refused with a reason rather than imported half-working.
      </p>
      <label>Sigma rule (YAML)
        <textarea rows={14} className="mono" spellCheck={false} value={text}
          onChange={(e) => { setText(e.target.value); setPreview(null); }} />
      </label>
      {preview && (
        <div className="mitigation" role="group" aria-label="Rule preview">
          <strong>{preview.name}</strong> · {preview.severity}
          <p>{preview.description}</p>
          <p className="muted">It will be added as a rule of your own, switched on. You can test and change it afterwards.</p>
        </div>
      )}
      {error && <div className="error" role="alert">{error}</div>}
      <div className="actions">
        <button disabled={busy || !text.trim()} onClick={() => run(async () => setPreview(await importSigmaRule(text, false)))}>
          Check the rule
        </button>
        <button className="primary" disabled={busy || !preview} onClick={() => run(async () => { await importSigmaRule(text, true); onSaved(); })}>
          Import rule
        </button>
        <button disabled={busy} onClick={onClose}>Cancel</button>
      </div>
    </div>
  );
}
