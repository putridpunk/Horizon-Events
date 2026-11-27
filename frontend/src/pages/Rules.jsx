import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { deleteCustomRule, listRules, updateRule } from "../services/api.js";
import { EmptyState, ErrorBanner, PageHeader, SeverityBadge } from "../components/common.jsx";
import { Drawer } from "../components/overlay.jsx";
import TechniqueBadges from "../components/TechniqueBadges.jsx";
import RuleEditor from "../components/rules/RuleEditor.jsx";
import RuleTuner from "../components/rules/RuleTuner.jsx";
import SigmaImport from "../components/rules/SigmaImport.jsx";

/** Every detection rule: switch them on and off, tune the built-in ones, write your own, and test any change on the past. */
export default function Rules() {
  const { data, error, reload } = usePolling(listRules, [], 0);
  const [panel, setPanel] = useState(null); // {kind: "new" | "sigma" | "edit" | "tune", rule?}
  const [actionError, setActionError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function act(fn) {
    setBusy(true);
    setActionError(null);
    try {
      await fn();
      await reload();
    } catch (e) {
      setActionError(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  const done = async () => { setPanel(null); await reload(); };
  const rules = data ?? [];
  const mine = rules.filter((r) => r.custom);
  const builtIn = rules.filter((r) => !r.custom);

  const table = (items) => (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Rule</th><th>Severity</th><th>On</th><th /></tr></thead>
        <tbody>
          {items.map((r) => (
            <tr key={r.id}>
              <td>
                {r.name}<div className="muted">{r.id}</div>
                <TechniqueBadges techniques={r.techniques} />
              </td>
              <td><SeverityBadge value={r.severity} /></td>
              <td>
                <input type="checkbox" checked={r.enabled} disabled={busy} aria-label={`${r.name} enabled`}
                  onChange={(e) => act(() => updateRule(r.id, { enabled: e.target.checked }))} />
              </td>
              <td className="actions">
                {r.custom ? (
                  <>
                    <button disabled={busy} onClick={() => setPanel({ kind: "edit", rule: r })} aria-label={`Edit ${r.name}`}>Edit</button>
                    <button disabled={busy} onClick={() => act(() => deleteCustomRule(r.id))} aria-label={`Delete ${r.name}`}>Delete</button>
                  </>
                ) : (
                  r.id !== "HZ-008" && (
                    <button disabled={busy} onClick={() => setPanel({ kind: "tune", rule: r })} aria-label={`Tune ${r.name}`}>Tune and test</button>
                  )
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  const titles = { new: "New rule", sigma: "Import a Sigma rule", edit: "Edit rule", tune: "Tune and test" };
  return (
    <>
      <PageHeader title="Detection rules" subtitle="What raises alerts, and how to change it safely" />
      <ErrorBanner error={error} />
      {actionError && <div className="error" role="alert">{actionError}</div>}
      <section className="card">
        <h2>Your rules</h2>
        <p className="muted">
          Rules you write yourself, or import from the Sigma format. Test each one on past events before relying on it.
        </p>
        {data && mine.length === 0 ? <EmptyState>You have not written any rules.</EmptyState> : table(mine)}
        <div className="actions">
          <button className="primary" onClick={() => setPanel({ kind: "new" })}>New rule…</button>
          <button onClick={() => setPanel({ kind: "sigma" })}>Import a Sigma rule…</button>
        </div>
      </section>
      <section className="card">
        <h2>Built-in rules</h2>
        <p className="muted">
          Switch a rule off, or choose <strong>Tune and test</strong> to change its severity and settings and see what the
          change would have flagged over the last days. Rules that need extra setup (such as the location rules) stay silent
          until it is done.
        </p>
        {data && table(builtIn)}
      </section>
      {panel && (
        <Drawer title={titles[panel.kind]} subtitle={panel.rule ? `${panel.rule.id} · ${panel.rule.name}` : null} onClose={() => setPanel(null)}>
          {panel.kind === "sigma" && <SigmaImport onSaved={done} onClose={() => setPanel(null)} />}
          {(panel.kind === "new" || panel.kind === "edit") && <RuleEditor rule={panel.rule ?? null} onSaved={done} onClose={() => setPanel(null)} />}
          {panel.kind === "tune" && <RuleTuner rule={panel.rule} onSaved={done} onClose={() => setPanel(null)} />}
        </Drawer>
      )}
    </>
  );
}
