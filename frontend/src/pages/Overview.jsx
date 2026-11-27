import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { getEventTypes, getOverview, getSeverity, getSourceIps, getTimeseries, listIncidents } from "../services/api.js";
import { EmptyState, ErrorBanner, PageHeader, StatCard } from "../components/common.jsx";
import { EventsOverTime, HorizontalBars, SeverityDoughnut } from "../charts/charts.jsx";
import AlertDrawer from "../components/AlertDrawer.jsx";
import AttentionPanel from "../components/AttentionPanel.jsx";
import IncidentDrawer from "../components/IncidentDrawer.jsx";
import {
  DEFAULT_PREFS, RANGES, WIDGETS, loadPrefs, rangeBucket, rangeStart, savePrefs,
} from "../lib/dashboardPrefs.js";

const TITLES = Object.fromEntries(WIDGETS.map((w) => [w.id, w.title]));

function Customize({ prefs, onChange, onClose }) {
  const move = (id, step) => {
    const order = [...prefs.order];
    const i = order.indexOf(id);
    const j = i + step;
    if (j < 0 || j >= order.length) return;
    [order[i], order[j]] = [order[j], order[i]];
    onChange({ ...prefs, order });
  };
  const toggle = (id) => onChange({
    ...prefs, hidden: prefs.hidden.includes(id) ? prefs.hidden.filter((h) => h !== id) : [...prefs.hidden, id],
  });
  return (
    <section className="card" aria-label="Customize the overview">
      <h2>Customize this page</h2>
      <p className="muted">Choose what to show and in what order. This is remembered in this browser only.</p>
      <ul className="widget-list">
        {prefs.order.map((id, i) => (
          <li key={id}>
            <label className="check">
              <input type="checkbox" checked={!prefs.hidden.includes(id)} onChange={() => toggle(id)} />
              <span>{TITLES[id]}</span>
            </label>
            <button onClick={() => move(id, -1)} disabled={i === 0} aria-label={`Move ${TITLES[id]} up`}>Up</button>
            <button onClick={() => move(id, 1)} disabled={i === prefs.order.length - 1} aria-label={`Move ${TITLES[id]} down`}>Down</button>
          </li>
        ))}
      </ul>
      <div className="toolbar">
        <label>Time range of the chart
          <select value={prefs.range} onChange={(e) => onChange({ ...prefs, range: e.target.value })}>
            {RANGES.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
          </select>
        </label>
        <button onClick={() => onChange({ ...DEFAULT_PREFS, order: [...DEFAULT_PREFS.order], hidden: [...DEFAULT_PREFS.hidden] })}>
          Back to the standard layout
        </button>
        <button className="primary" onClick={onClose}>Done</button>
      </div>
    </section>
  );
}

export default function Overview() {
  const [alertId, setAlertId] = useState(null);
  const [incidentId, setIncidentId] = useState(null);
  const [prefs, setPrefs] = useState(() => loadPrefs());
  const [editing, setEditing] = useState(false);
  const shown = (id) => !prefs.hidden.includes(id);
  const update = (next) => { setPrefs(next); savePrefs(next); };

  const stats = usePolling(getOverview, [], 10000);
  const series = usePolling(
    () => getTimeseries({ bucket: rangeBucket(prefs.range), ...(rangeStart(prefs.range) ? { start: rangeStart(prefs.range) } : {}) }),
    [prefs.range], 10000);
  const openIncidents = usePolling(() => listIncidents({ status: "OPEN", limit: 1 }), [], 10000);
  const types = usePolling(() => (shown("types") ? getEventTypes() : Promise.resolve(null)), [shown("types")], 10000);
  const ips = usePolling(() => (shown("ips") ? getSourceIps() : Promise.resolve(null)), [shown("ips")], 10000);
  const severity = usePolling(() => (shown("severity") ? getSeverity() : Promise.resolve(null)), [shown("severity")], 10000);
  const o = stats.data;
  const refresh = () => { stats.reload(); series.reload(); openIncidents.reload(); };

  const panel = (id, children) => <section className="card" key={id}><div className="card-header"><h2>{TITLES[id]}</h2></div>{children}</section>;
  const widgets = {
    stats: () => (
      <div className="grid cols-4" style={{ marginBottom: 16 }} key="stats">
        <StatCard label="Events collected" value={o?.total_events} tone="accent" />
        <StatCard label="Open alerts" value={o?.open_alerts} />
        <StatCard label="Open incidents" value={openIncidents.data?.total} />
        <StatCard label="Critical alerts" value={o?.critical_alerts} tone="critical" />
      </div>
    ),
    attention: () => <AttentionPanel key="attention" onOpenAlert={setAlertId} onOpenIncident={setIncidentId} />,
    timeline: () => panel("timeline", series.data?.length ? (
      <div className="chart-box"><EventsOverTime points={series.data} /></div>
    ) : (
      <EmptyState title="No events yet">
        Turn on system logs under Data sources, or import a log file, and activity will appear here.
      </EmptyState>
    )),
    types: () => panel("types", types.data?.length ? <HorizontalBars items={types.data} /> : <EmptyState>No events yet.</EmptyState>),
    ips: () => panel("ips", ips.data?.length ? <HorizontalBars items={ips.data} tone="high" /> : <EmptyState>No addresses yet.</EmptyState>),
    severity: () => panel("severity", severity.data?.some((s) => s.count) ? <SeverityDoughnut items={severity.data} /> : <EmptyState>No alerts yet.</EmptyState>),
  };

  // Everything but the key numbers sits in a two-column grid; the key numbers span the page wherever they are placed.
  const blocks = [];
  let row = [];
  for (const id of prefs.order.filter(shown)) {
    if (id === "stats") {
      if (row.length) blocks.push(<div className="grid cols-2" key={`row-${blocks.length}`}>{row}</div>);
      row = [];
      blocks.push(widgets.stats());
    } else {
      row.push(widgets[id]());
    }
  }
  if (row.length) blocks.push(<div className="grid cols-2" key={`row-${blocks.length}`}>{row}</div>);

  return (
    <>
      <PageHeader title="Security overview" subtitle="What is happening in the monitored environment right now">
        <button onClick={() => setEditing((e) => !e)} aria-expanded={editing}>Customize</button>
      </PageHeader>
      <ErrorBanner error={stats.error || series.error || openIncidents.error} />
      {editing && <Customize prefs={prefs} onChange={update} onClose={() => setEditing(false)} />}
      {blocks.length ? blocks : <EmptyState>Everything is hidden. Choose Customize to bring something back.</EmptyState>}
      {alertId && <AlertDrawer alertId={alertId} onClose={() => setAlertId(null)} onChanged={refresh} />}
      {incidentId && <IncidentDrawer incidentId={incidentId} others={[]} onClose={() => setIncidentId(null)} onChanged={refresh} />}
    </>
  );
}
