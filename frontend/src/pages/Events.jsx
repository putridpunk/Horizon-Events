import { useEffect, useState } from "react";
import usePolling from "../services/usePolling.js";
import { getEvent, listEvents } from "../services/api.js";
import { EVENT_TYPES, SEVERITIES, SOURCES, fmtTime } from "../services/constants.js";
import { EmptyState, ErrorBanner, PageHeader, Pager, SeverityBadge } from "../components/common.jsx";
import EventDetail from "../components/EventDetail.jsx";

const LIMIT = 25;

export default function Events() {
  const [qInput, setQInput] = useState("");
  const [filters, setFilters] = useState({ q: "", source: "", event_type: "", severity: "" });
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    const id = setTimeout(() => { setFilters((f) => ({ ...f, q: qInput })); setOffset(0); }, 300);
    return () => clearTimeout(id);
  }, [qInput]);

  const setFilter = (key) => (e) => { setFilters((f) => ({ ...f, [key]: e.target.value })); setOffset(0); };
  const { data, error } = usePolling(() => listEvents({ ...filters, limit: LIMIT, offset }), [filters, offset], 5000);

  const open = async (id) => setSelected(await getEvent(id));

  return (
    <>
      <PageHeader title="Event monitoring" subtitle="Live feed of normalised events (refreshes every 5 seconds)" />
      <ErrorBanner error={error} />
      <div className="toolbar">
        <input type="search" placeholder="Search message, user, IP, host…" value={qInput} onChange={(e) => setQInput(e.target.value)} />
        <select value={filters.source} onChange={setFilter("source")}>
          <option value="">All sources</option>{SOURCES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={filters.event_type} onChange={setFilter("event_type")}>
          <option value="">All categories</option>{EVENT_TYPES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={filters.severity} onChange={setFilter("severity")}>
          <option value="">All severities</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>
      <section className="card">
        {data?.items.length ? (
          <>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Source</th><th>User</th><th>IP</th><th>Message</th></tr></thead>
                <tbody>
                  {data.items.map((e) => (
                    <tr key={e.id} className="clickable" onClick={() => open(e.id)}>
                      <td className="mono">{fmtTime(e.timestamp)}</td>
                      <td><SeverityBadge value={e.severity} /></td>
                      <td>{e.event_type}</td>
                      <td>{e.source}</td>
                      <td>{e.username || "-"}</td>
                      <td className="mono">{e.source_ip || "-"}</td>
                      <td className="muted">{e.message.slice(0, 80)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager offset={offset} limit={LIMIT} total={data.total} onChange={setOffset} />
          </>
        ) : (
          <EmptyState>No events match. Import logs or adjust the filters.</EmptyState>
        )}
      </section>
      <EventDetail event={selected} onClose={() => setSelected(null)} />
    </>
  );
}
