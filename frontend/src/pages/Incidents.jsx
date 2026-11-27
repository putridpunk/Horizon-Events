import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { listIncidents } from "../services/api.js";
import { SEVERITIES, STATUSES } from "../services/constants.js";
import Icon from "../components/ui/Icon.jsx";
import Time from "../components/ui/Time.jsx";
import rowProps from "../components/ui/rowProps.js";
import { EmptyState, ErrorBanner, PageHeader, Pager, SeverityBadge, StatusBadge } from "../components/common.jsx";
import IncidentDrawer from "../components/IncidentDrawer.jsx";

const LIMIT = 20;

export default function Incidents() {
  const [filters, setFilters] = useState({ severity: "", status: "" });
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState(null);
  const { data, error, reload } = usePolling(() => listIncidents({ ...filters, limit: LIMIT, offset }), [filters, offset], 10000);
  const all = usePolling(() => listIncidents({ limit: 200 }), [], 10000);
  const setFilter = (key) => (e) => { setFilters((f) => ({ ...f, [key]: e.target.value })); setOffset(0); };
  const refresh = () => { reload(); all.reload(); };
  const others = (all.data?.items ?? []).filter((i) => i.id !== selected && i.status !== "RESOLVED");

  return (
    <>
      <PageHeader title="Incidents" subtitle="Related alerts grouped by shared IP address or account, for investigation" />
      <ErrorBanner error={error} />
      <div className="toolbar">
        <select value={filters.severity} onChange={setFilter("severity")}>
          <option value="">All severities</option>{SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={filters.status} onChange={setFilter("status")}>
          <option value="">All statuses</option>{STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>
      <section className="card">
        {data?.items.length ? (
          <>
            <div className="table-wrap">
              <table>
                <thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Alerts</th><th>Status</th><th>Last activity</th><th aria-label="Open"></th></tr></thead>
                <tbody>
                  {data.items.map((i) => (
                    <tr key={i.id} {...rowProps(() => setSelected(i.id))}>
                      <td className="mono">{i.incident_id}</td>
                      <td><SeverityBadge value={i.severity} /></td>
                      <td>{i.title}</td>
                      <td>{i.alert_count}</td>
                      <td><StatusBadge value={i.status} /></td>
                      <td><Time value={i.last_activity} /></td>
                      <td className="chevron"><Icon name="chevron-right" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />
          </>
        ) : (
          <EmptyState>No incidents match. Incidents are created automatically as alerts are raised.</EmptyState>
        )}
      </section>
      {selected && (
        <IncidentDrawer incidentId={selected} others={others} onClose={() => setSelected(null)} onChanged={refresh} />
      )}
    </>
  );
}
