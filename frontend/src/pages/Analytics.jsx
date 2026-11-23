import usePolling from "../services/usePolling.js";
import { getEventTypes, getMitreStats, getRuleStats, getSeverity, getSourceIps, getTimeseries } from "../services/api.js";
import { fmtTime } from "../services/constants.js";
import { EmptyState, ErrorBanner, PageHeader } from "../components/common.jsx";
import ModelCard from "../components/ModelCard.jsx";
import MitrePanel from "../components/MitrePanel.jsx";
import IntelCard from "../components/IntelCard.jsx";
import { EventsOverTime, HorizontalBars, SeverityDoughnut } from "../charts/charts.jsx";

function Panel({ title, empty, children }) {
  return (
    <section className="card">
      <h2>{title}</h2>
      {empty ? <EmptyState /> : <div className="chart-box">{children}</div>}
    </section>
  );
}

export default function Analytics() {
  const { data, error } = usePolling(async () => {
    const [series, types, ips, severity, rules, mitre] = await Promise.all([
      getTimeseries({ bucket: "hour" }), getEventTypes(), getSourceIps(), getSeverity(), getRuleStats(), getMitreStats(),
    ]);
    return { series, types, ips, severity, rules, mitre };
  }, [], 15000);

  const d = data;
  const noAlerts = !d || d.severity.every((s) => s.count === 0);
  return (
    <>
      <PageHeader title="Analytics" subtitle="Trends and distributions across all collected data" />
      <ErrorBanner error={error} />
      <div className="grid cols-2">
        <Panel title="Events over time" empty={!d?.series.length}>{d && <EventsOverTime points={d.series} />}</Panel>
        <Panel title="Alert severity distribution" empty={noAlerts}>{d && <SeverityDoughnut items={d.severity} />}</Panel>
        <Panel title="Most frequent event types" empty={!d?.types.length}>{d && <HorizontalBars items={d.types} />}</Panel>
        <Panel title="Most common source IPs" empty={!d?.ips.length}>{d && <HorizontalBars items={d.ips} color="#ff9248" />}</Panel>
      </div>
      <MitrePanel stats={d?.mitre} />
      <ModelCard />
      <IntelCard />
      <section className="card" style={{ marginTop: 16 }}>
        <h2>Detection rule statistics</h2>
        {d?.rules.length ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Rule</th><th>Name</th><th>Severity</th><th>Enabled</th><th>Alerts</th><th>Last triggered</th></tr></thead>
              <tbody>
                {d.rules.map((r) => (
                  <tr key={r.rule_id}>
                    <td className="mono">{r.rule_id}</td><td>{r.name}</td><td>{r.severity}</td>
                    <td>{r.enabled ? "yes" : "no"}</td><td>{r.alerts}</td><td className="muted">{fmtTime(r.last_triggered)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState>Rule statistics appear after the first import.</EmptyState>
        )}
      </section>
    </>
  );
}
