import usePolling from "../services/usePolling.js";
import { listAlerts, listIncidents } from "../services/api.js";
import { parseTimestamp } from "../lib/time.js";
import { ErrorBanner } from "./common.jsx";
import IntelBadge from "./IntelBadge.jsx";
import EmptyState from "./ui/EmptyState.jsx";
import Icon from "./ui/Icon.jsx";
import SeverityBadge from "./ui/SeverityBadge.jsx";
import Time from "./ui/Time.jsx";

const MAX_ALERTS = 6;
const MAX_INCIDENTS = 4;
const newestFirst = (a, b) => (parseTimestamp(b.last_seen ?? b.last_activity)?.getTime() ?? 0) -
  (parseTimestamp(a.last_seen ?? a.last_activity)?.getTime() ?? 0);

/** What to look at first: open critical alerts, then open high ones, then incidents nobody has started on. */
export default function AttentionPanel({ onOpenAlert, onOpenIncident }) {
  const critical = usePolling(() => listAlerts({ status: "OPEN", severity: "critical", limit: MAX_ALERTS }), [], 10000);
  const high = usePolling(() => listAlerts({ status: "OPEN", severity: "high", limit: MAX_ALERTS }), [], 10000);
  const incidents = usePolling(() => listIncidents({ status: "OPEN", limit: MAX_INCIDENTS }), [], 10000);

  const loading = critical.loading || high.loading || incidents.loading;
  const error = critical.error || high.error || incidents.error;
  const merged = [
    ...[...(critical.data?.items ?? [])].sort(newestFirst),
    ...[...(high.data?.items ?? [])].sort(newestFirst),
  ];
  const alerts = merged.filter((a, i) => merged.findIndex((b) => b.id === a.id) === i).slice(0, MAX_ALERTS);
  const openIncidents = [...(incidents.data?.items ?? [])].sort(newestFirst).slice(0, MAX_INCIDENTS);
  const nothing = !alerts.length && !openIncidents.length;

  return (
    <section className="card" aria-label="Needs attention">
      <div className="card-header"><h2>Needs attention</h2></div>
      <ErrorBanner error={error} />
      {loading && nothing && <p className="muted">Loading…</p>}
      {!loading && nothing && !error && (
        <EmptyState title="Nothing needs attention">
          No open critical or high alerts, and no incident is waiting for someone to start on it.
        </EmptyState>
      )}
      {alerts.map((a) => (
        <button key={`a${a.id}`} className="attention-row" onClick={() => onOpenAlert(a.id)}>
          <SeverityBadge value={a.severity} />
          <span>
            <span className="title">{a.rule_name}</span>
            <span className="muted"> · {a.source_ip || a.username || a.alert_id}</span>
            <IntelBadge intel={a.intel} />
          </span>
          <Time value={a.last_seen} />
          <Icon name="chevron-right" />
        </button>
      ))}
      {openIncidents.map((i) => (
        <button key={`i${i.id}`} className="attention-row" onClick={() => onOpenIncident(i.id)}>
          <SeverityBadge value={i.severity} />
          <span>
            <span className="title">{i.title}</span>
            <span className="muted"> · {i.incident_id} · {i.alert_count} {i.alert_count === 1 ? "alert" : "alerts"}</span>
          </span>
          <Time value={i.last_activity} />
          <Icon name="chevron-right" />
        </button>
      ))}
    </section>
  );
}
