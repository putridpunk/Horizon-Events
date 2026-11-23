import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { listAlerts } from "../services/api.js";
import { SEVERITIES, STATUSES, fmtTime } from "../services/constants.js";
import { EmptyState, ErrorBanner, PageHeader, Pager, SeverityBadge, StatusBadge } from "../components/common.jsx";
import AlertDrawer from "../components/AlertDrawer.jsx";
import TechniqueBadges from "../components/TechniqueBadges.jsx";
import IntelBadge from "../components/IntelBadge.jsx";

const LIMIT = 20;

export default function Alerts() {
  const [filters, setFilters] = useState({ severity: "", status: "" });
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState(null);
  const { data, error, reload } = usePolling(() => listAlerts({ ...filters, limit: LIMIT, offset }), [filters, offset], 10000);
  const setFilter = (key) => (e) => { setFilters((f) => ({ ...f, [key]: e.target.value })); setOffset(0); };

  return (
    <>
      <PageHeader title="Alerts" subtitle="Suspicious activity flagged by the detection engine, highest severity first" />
      <ErrorBanner error={error} />
      <div className="toolbar">
        <select value={filters.severity} onChange={setFilter("severity")}>
          <option value="">All severities</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={filters.status} onChange={setFilter("status")}>
          <option value="">All statuses</option>{STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>
      <section className="card">
        {data?.items.length ? (
          <>
            <div className="table-wrap">
              <table>
                <thead><tr><th>ID</th><th>Severity</th><th>Rule</th><th>Source IP</th><th>Account</th><th>Count</th><th>Status</th><th>Last activity</th></tr></thead>
                <tbody>
                  {data.items.map((a) => (
                    <tr key={a.id} className="clickable" onClick={() => setSelected(a.id)}>
                      <td className="mono">{a.alert_id}</td>
                      <td><SeverityBadge value={a.severity} /></td>
                      <td>{a.rule_name}<div className="muted">{a.rule_id}</div><TechniqueBadges techniques={a.techniques} /></td>
                      <td className="mono">{a.source_ip || "-"}<IntelBadge intel={a.intel} /></td>
                      <td>{a.username || "-"}</td>
                      <td>{a.occurrences}</td>
                      <td><StatusBadge value={a.status} /></td>
                      <td className="muted">{fmtTime(a.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />
          </>
        ) : (
          <EmptyState>No alerts match the current filters.</EmptyState>
        )}
      </section>
      {selected && <AlertDrawer alertId={selected} onClose={() => setSelected(null)} onChanged={reload} />}
    </>
  );
}
