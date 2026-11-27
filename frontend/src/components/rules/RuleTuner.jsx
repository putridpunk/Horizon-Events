import { useState } from "react";
import { replayRule, updateRule } from "../../services/api.js";
import { SEVERITIES } from "../../services/constants.js";
import ReplayResult from "./ReplayResult.jsx";

const DAYS = [1, 7, 30, 90];

/** Change a built-in rule's severity and settings, and see what the change would have flagged before saving it. */
export default function RuleTuner({ rule, onSaved, onClose }) {
  const [severity, setSeverity] = useState(rule.severity);
  const [text, setText] = useState(JSON.stringify(rule.params ?? {}, null, 2));
  const [days, setDays] = useState(7);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  function parse() {
    try {
      const value = JSON.parse(text || "{}");
      if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error();
      return value;
    } catch {
      throw new Error("The settings must be a JSON object, for example {\"threshold\": 5}.");
    }
  }

  async function run(action) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  const test = () => run(async () => setResult(await replayRule({ rule_id: rule.id, severity, params: parse(), days })));
  const save = () => run(async () => {
    await updateRule(rule.id, { severity, params: parse() });
    onSaved();
  });

  return (
    <div className="settings-form">
      <p className="muted">{rule.description}</p>
      <label>Severity
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>{SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}</select>
      </label>
      {Object.keys(rule.params ?? {}).length > 0 ? (
        <label>Settings (JSON)
          <textarea rows={Math.min(12, text.split("\n").length + 1)} value={text} spellCheck={false}
            onChange={(e) => setText(e.target.value)} className="mono" />
        </label>
      ) : (
        <p className="muted">This rule has no settings to change besides its severity.</p>
      )}
      <div className="toolbar">
        <label>Look back
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
            {DAYS.map((d) => <option key={d} value={d}>{d} {d === 1 ? "day" : "days"}</option>)}
          </select>
        </label>
        <button disabled={busy} onClick={test}>Test these settings</button>
      </div>
      <p className="muted">Shows what the rule would have flagged with these settings. Nothing is saved until you choose Save.</p>
      {result && <ReplayResult result={result} />}
      {error && <div className="error" role="alert">{error}</div>}
      <div className="actions">
        <button className="primary" disabled={busy} onClick={save}>Save</button>
        <button disabled={busy} onClick={onClose}>Cancel</button>
      </div>
    </div>
  );
}
