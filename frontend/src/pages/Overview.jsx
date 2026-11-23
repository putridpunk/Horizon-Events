import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { getOverview, getTimeseries, listAlerts } from "../services/api.js";
import { fmtTime } from "../services/constants.js";
import { EmptyState, ErrorBanner, PageHeader, SeverityBadge, StatCard, StatusBadge } from "../components/common.jsx";
import { EventsOverTime } from "../charts/charts.jsx";
import ImportButton from "../components/ImportButton.jsx";
import AlertDrawer from "../components/AlertDrawer.jsx";
import LiveCard from "../components/LiveCard.jsx";

export default function Overview() {
  const [selected, setSelected] = useState(null);
  const stats = usePolling(getOverview, [], 10000);
  const series = usePolling(() => getTimeseries({ bucket: "hour" }), [], 10000);
  const alerts = usePolling(() => listAlerts({ limit: 6 }), [], 10000);
  const o = stats.data;
  const refresh = () => { stats.reload(); series.reload(); alerts.reload(); };

  return (
    <>
      <PageHeader title="Security overview" subtitle="Current state of the monitored environment">
        <ImportButton onDone={refresh} />
      </PageHeader>
      <ErrorBanner error={stats.error || series.error || alerts.error} />
      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <StatCard label="Events collected" value={o?.total_events} tone="accent" />
        <StatCard label="Alerts generated" value={o?.total_alerts} />
        <StatCard label="Critical alerts" value={o?.critical_alerts} tone="critical" />
        <StatCard label="High alerts" value={o?.high_alerts} tone="high" />
      </div>
      <div className="grid cols-2">
        <section className="card">
          <h2>Events processed over time</h2>
          {series.data?.length ? (
            <div className="chart-box"><EventsOverTime points={series.data} /></div>
          ) : (
            <EmptyState>No events yet. Import a log file to get started.</EmptyState>
          )}
        </section>
        <section className="card">
          <h2>Latest alerts {o ? <span className="muted">· {o.open_alerts} open</span> : null}</h2>
          {alerts.data?.items.length ? (
            <div className="table-wrap">
              <table>
                <tbody>
                  {alerts.data.items.map((a) => (
                    <tr key={a.id} className="clickable" onClick={() => setSelected(a.id)}>
                      <td><SeverityBadge value={a.severity} /></td>
                      <td>{a.rule_name}<div className="muted mono">{a.source_ip || a.username || ""}</div></td>
                      <td><StatusBadge value={a.status} /></td>
                      <td className="muted">{fmtTime(a.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState>No alerts. Nothing suspicious detected yet.</EmptyState>
          )}
        </section>
      </div>
      <LiveCard />
      {selected && <AlertDrawer alertId={selected} onClose={() => setSelected(null)} onChanged={refresh} />}
    </>
  );
}
