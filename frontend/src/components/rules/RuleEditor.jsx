import { useState } from "react";
import { createCustomRule, replaceCustomRule, replayRule } from "../../services/api.js";
import { SEVERITIES, EVENT_TYPES } from "../../services/constants.js";
import ReplayResult from "./ReplayResult.jsx";

export const FIELDS = ["event_type", "severity", "username", "source_ip", "host", "service", "source", "message", "raw"];
export const OPS = [
  ["eq", "is"], ["ne", "is not"], ["contains", "contains"], ["not_contains", "does not contain"],
  ["startswith", "starts with"], ["endswith", "ends with"], ["in", "is one of (comma separated)"],
  ["glob", "matches pattern (* = anything)"], ["cidr", "is in address block"], ["severity_gte", "is at least"],
  ["severity_lte", "is at most"], ["present", "is present"], ["absent", "is missing"],
];
const NO_VALUE = ["present", "absent"];
const DAYS = [1, 7, 30, 90];
const BLANK = {
  name: "", description: "", severity: "medium", match: "all", threshold: 1, window_minutes: 10, group_by: "none",
  conditions: [{ field: "event_type", op: "eq", value: "authentication_failure" }], nested: null,
};

const isPlain = (c) => c && typeof c.field === "string" && c.op !== "raw_field" && c.name === undefined;

/** The editor handles one flat list of conditions; anything more complex (for example from a Sigma rule) is kept as is. */
export function fromRule(rule) {
  if (!rule) return { ...BLANK, conditions: BLANK.conditions.map((c) => ({ ...c })) };
  const p = rule.params ?? {};
  const when = p.when ?? {};
  const base = {
    name: rule.name, description: rule.description === rule.name ? "" : rule.description, severity: rule.severity,
    threshold: p.threshold ?? 1, window_minutes: p.window_minutes ?? 10, group_by: p.group_by ?? "none", nested: null,
  };
  const list = when.all ?? when.any ?? (when.field ? [when] : null);
  if (list && list.every(isPlain)) {
    return {
      ...base, match: when.any ? "any" : "all",
      conditions: list.map((c) => ({ field: c.field, op: c.op, value: Array.isArray(c.value) ? c.value.join(", ") : c.value ?? "" })),
    };
  }
  return { ...base, match: "all", conditions: [], nested: when };
}

export function toParams(f) {
  const when = f.nested ?? {
    [f.match]: f.conditions.map((c) => (NO_VALUE.includes(c.op) ? { field: c.field, op: c.op } : { field: c.field, op: c.op, value: c.value })),
  };
  return { when, threshold: Number(f.threshold), window_minutes: Number(f.window_minutes), group_by: f.group_by };
}

/** Write or change a rule of your own, and try it on the past before it raises a single alert. */
export default function RuleEditor({ rule, onSaved, onClose }) {
  const [f, setF] = useState(() => fromRule(rule));
  const [days, setDays] = useState(7);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const set = (key) => (e) => setF((s) => ({ ...s, [key]: e.target.value }));
  const setCond = (i, key) => (e) => setF((s) => ({
    ...s, conditions: s.conditions.map((c, j) => (j === i ? { ...c, [key]: e.target.value } : c)),
  }));
  const addCond = () => setF((s) => ({ ...s, conditions: [...s.conditions, { field: "username", op: "eq", value: "" }] }));
  const removeCond = (i) => setF((s) => ({ ...s, conditions: s.conditions.filter((_, j) => j !== i) }));

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

  const test = () => run(async () => {
    setResult(await replayRule({ name: f.name || "Draft rule", severity: f.severity, params: toParams(f), days }));
  });
  const save = (e) => {
    e.preventDefault();
    return run(async () => {
      const body = { name: f.name, description: f.description, severity: f.severity, params: toParams(f), enabled: rule?.enabled ?? true };
      await (rule ? replaceCustomRule(rule.id, body) : createCustomRule(body));
      onSaved();
    });
  };

  return (
    <form className="settings-form" onSubmit={save} aria-label="Rule editor">
      <label>Name<input required maxLength={100} value={f.name} onChange={set("name")} /></label>
      <label>What it means (shown on its alerts)
        <input maxLength={1000} value={f.description} onChange={set("description")} />
      </label>
      <label>Severity
        <select value={f.severity} onChange={set("severity")}>{SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}</select>
      </label>

      <fieldset>
        <legend>When an event matches</legend>
        {f.nested ? (
          <p className="muted">
            This rule's conditions are more complex than this editor shows (for example, imported from a Sigma rule). They are
            kept as they are; you can still change the name, severity and counts.
          </p>
        ) : (
          <>
            <label>
              <select value={f.match} onChange={set("match")} aria-label="Match mode">
                <option value="all">all of these</option><option value="any">any of these</option>
              </select>
            </label>
            {f.conditions.map((c, i) => (
              <div className="toolbar" key={i} role="group" aria-label={`Condition ${i + 1}`}>
                <select value={c.field} onChange={setCond(i, "field")} aria-label={`Condition ${i + 1} field`}>
                  {FIELDS.map((x) => <option key={x} value={x}>{x}</option>)}
                </select>
                <select value={c.op} onChange={setCond(i, "op")} aria-label={`Condition ${i + 1} test`}>
                  {OPS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
                </select>
                {!NO_VALUE.includes(c.op) && (
                  <input value={c.value} onChange={setCond(i, "value")} aria-label={`Condition ${i + 1} value`}
                    list={c.field === "event_type" ? "rule-event-types" : undefined} />
                )}
                <button type="button" onClick={() => removeCond(i)} disabled={f.conditions.length === 1}
                  aria-label={`Remove condition ${i + 1}`}>Remove</button>
              </div>
            ))}
            <datalist id="rule-event-types">{EVENT_TYPES.map((t) => <option key={t} value={t} />)}</datalist>
            <button type="button" onClick={addCond}>Add a condition</button>
          </>
        )}
      </fieldset>

      <fieldset>
        <legend>Raise an alert</legend>
        <div className="toolbar">
          <label>after at least
            <input type="number" min="1" max="10000" value={f.threshold} onChange={set("threshold")} style={{ width: 90 }} />
          </label>
          <span>matching events</span>
          {Number(f.threshold) > 1 && (
            <label>within
              <input type="number" min="1" max="10080" value={f.window_minutes} onChange={set("window_minutes")} style={{ width: 90 }} />
            </label>
          )}
          {Number(f.threshold) > 1 && <span>minutes</span>}
        </div>
        <label>Count separately for each
          <select value={f.group_by} onChange={set("group_by")}>
            <option value="none">(everything together)</option>
            {["source_ip", "username", "host", "service"].map((g) => <option key={g} value={g}>{g}</option>)}
          </select>
        </label>
      </fieldset>

      <fieldset>
        <legend>Try it on the past</legend>
        <div className="toolbar">
          <label>Look back
            <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
              {DAYS.map((d) => <option key={d} value={d}>{d} {d === 1 ? "day" : "days"}</option>)}
            </select>
          </label>
          <button type="button" disabled={busy} onClick={test}>Test this rule</button>
        </div>
        <p className="muted">Shows what it would have flagged. Nothing is saved and no notification is sent.</p>
        {result && <ReplayResult result={result} />}
      </fieldset>

      {error && <div className="error" role="alert">{error}</div>}
      <div className="actions">
        <button type="submit" className="primary" disabled={busy}>{rule ? "Save changes" : "Create rule"}</button>
        <button type="button" disabled={busy} onClick={onClose}>Cancel</button>
      </div>
    </form>
  );
}
