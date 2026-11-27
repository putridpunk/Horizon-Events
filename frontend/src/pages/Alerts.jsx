import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { listAlertTags, listAlerts } from "../services/api.js";
import { SEVERITIES, STATUSES } from "../services/constants.js";
import Icon from "../components/ui/Icon.jsx";
import Time from "../components/ui/Time.jsx";
import rowProps from "../components/ui/rowProps.js";
import { EmptyState, ErrorBanner, PageHeader, Pager, SeverityBadge, StatusBadge } from "../components/common.jsx";
import AlertDrawer from "../components/AlertDrawer.jsx";
import TechniqueBadges from "../components/TechniqueBadges.jsx";
import IntelBadge from "../components/IntelBadge.jsx";

const LIMIT = 20;

export default function Alerts() {
  const [filters, setFilters] = useState({ severity: "", status: "", assignee: "", tag: "" });
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState(null);
  const { data, error, reload } = usePolling(() => listAlerts({ ...filters, limit: LIMIT, offset }), [filters, offset], 10000);
  const { data: labels } = usePolling(listAlertTags, [], 30000);
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
        <select value={filters.assignee} onChange={setFilter("assignee")} aria-label="Owner">
          <option value="">All owners</option>
          <option value="unassigned">Unassigned</option>
          {(labels?.assignees ?? []).map((a) => <option key={a}>{a}</option>)}
        </select>
        {(labels?.tags ?? []).length > 0 && (
          <select value={filters.tag} onChange={setFilter("tag")} aria-label="Tag">
            <option value="">All tags</option>{labels.tags.map((t) => <option key={t}>{t}</option>)}
          </select>
        )}
      </div>
      <section className="card">
        {data?.items.length ? (
          <>
            <div className="table-wrap">
              <table>
                <thead><tr><th>ID</th><th>Severity</th><th>Rule</th><th>Source IP</th><th>Account</th><th>Owner</th><th>Count</th><th>Status</th><th>Last activity</th><th aria-label="Open"></th></tr></thead>
                <tbody>
                  {data.items.map((a) => (
                    <tr key={a.id} {...rowProps(() => setSelected(a.id))}>
                      <td className="mono">{a.alert_id}</td>
                      <td><SeverityBadge value={a.severity} /></td>
                      <td>{a.rule_name}<div className="muted">{a.rule_id}</div><TechniqueBadges techniques={a.techniques} />{(a.tags ?? []).map((t) => <span key={t} className="badge tag">{t}</span>)}</td>
                      <td className="mono">{a.source_ip || "-"}<IntelBadge intel={a.intel} /></td>
                      <td>{a.username || "-"}</td>
                      <td>{a.assignee || "-"}{a.sla_breached && <span className="badge sla-late" title="Waiting longer than its target"> late</span>}</td>
                      <td>{a.occurrences}</td>
                      <td><StatusBadge value={a.status} /></td>
                      <td><Time value={a.last_seen} /></td>
                      <td className="chevron"><Icon name="chevron-right" /></td>
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
