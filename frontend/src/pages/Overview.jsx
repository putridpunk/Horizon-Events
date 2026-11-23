import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { getOverview, getTimeseries, listIncidents } from "../services/api.js";
import { EmptyState, ErrorBanner, PageHeader, StatCard } from "../components/common.jsx";
import { EventsOverTime } from "../charts/charts.jsx";
import AlertDrawer from "../components/AlertDrawer.jsx";
import AttentionPanel from "../components/AttentionPanel.jsx";
import IncidentDrawer from "../components/IncidentDrawer.jsx";

export default function Overview() {
  const [alertId, setAlertId] = useState(null);
  const [incidentId, setIncidentId] = useState(null);
  const stats = usePolling(getOverview, [], 10000);
  const series = usePolling(() => getTimeseries({ bucket: "hour" }), [], 10000);
  const openIncidents = usePolling(() => listIncidents({ status: "OPEN", limit: 1 }), [], 10000);
  const o = stats.data;
  const refresh = () => { stats.reload(); series.reload(); openIncidents.reload(); };

  return (
    <>
      <PageHeader title="Security overview" subtitle="What is happening in the monitored environment right now" />
      <ErrorBanner error={stats.error || series.error || openIncidents.error} />
      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <StatCard label="Events collected" value={o?.total_events} tone="accent" />
        <StatCard label="Open alerts" value={o?.open_alerts} />
        <StatCard label="Open incidents" value={openIncidents.data?.total} />
        <StatCard label="Critical alerts" value={o?.critical_alerts} tone="critical" />
      </div>
      <div className="grid cols-2">
        <AttentionPanel onOpenAlert={setAlertId} onOpenIncident={setIncidentId} />
        <section className="card">
          <div className="card-header"><h2>Events over time</h2></div>
          {series.data?.length ? (
            <div className="chart-box"><EventsOverTime points={series.data} /></div>
          ) : (
            <EmptyState title="No events yet">
              Turn on system logs under Data sources, or import a log file, and activity will appear here.
            </EmptyState>
          )}
        </section>
      </div>
      {alertId && <AlertDrawer alertId={alertId} onClose={() => setAlertId(null)} onChanged={refresh} />}
      {incidentId && <IncidentDrawer incidentId={incidentId} others={[]} onClose={() => setIncidentId(null)} onChanged={refresh} />}
    </>
  );
}
