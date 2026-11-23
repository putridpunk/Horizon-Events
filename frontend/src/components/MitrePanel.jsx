import { EmptyState } from "./common.jsx";

export default function MitrePanel({ stats }) {
  const tactics = stats?.tactics ?? [];
  const techniques = stats?.techniques ?? [];
  const max = Math.max(1, ...tactics.map((t) => t.alerts));
  const hit = techniques.some((t) => t.alerts > 0);
  return (
    <section className="card" style={{ marginTop: 16 }}>
      <h2>MITRE ATT&amp;CK coverage</h2>
      {!tactics.length ? (
        <EmptyState />
      ) : (
        <div className="grid cols-2">
          <div>
            {tactics.map((t) => (
              <div key={t.tactic} className="bar-row">
                <span className="name">{t.tactic}</span>
                <span className="bar"><span style={{ width: `${(t.alerts / max) * 100}%` }} /></span>
                <span>{t.alerts}</span>
              </div>
            ))}
            {!hit && <p className="muted">No alerts mapped to techniques yet.</p>}
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Technique</th><th>Name</th><th>Alerts</th></tr></thead>
              <tbody>
                {techniques.map((t) => (
                  <tr key={t.id}>
                    <td><a className="mono" href={t.url} target="_blank" rel="noopener noreferrer">{t.id}</a></td>
                    <td>{t.name}<div className="muted">{t.tactics.join(", ")}</div></td>
                    <td>{t.alerts}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      <p className="muted" style={{ marginBottom: 0 }}>
        Mappings are context for investigation, not proof of a technique being used.
      </p>
    </section>
  );
}
