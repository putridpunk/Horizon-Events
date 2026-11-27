import { useEffect, useState } from "react";
import usePolling from "../services/usePolling.js";
import {
  createSavedSearch, deleteSavedSearch, exportEventsUrl, getEvent, listEvents, listSavedSearches,
} from "../services/api.js";
import { EVENT_TYPES, SEVERITIES, SOURCES, fmtTime } from "../services/constants.js";
import Icon from "../components/ui/Icon.jsx";
import rowProps from "../components/ui/rowProps.js";
import { EmptyState, ErrorBanner, PageHeader, Pager, SeverityBadge } from "../components/common.jsx";
import EventDetail from "../components/EventDetail.jsx";

const LIMIT = 25;

const EXAMPLES = [
  ["failed login", "words that all appear in the message, account, address or log line"],
  ["user:admin ip:203.0.113.7", "an account and an address"],
  ["ip:10.0.0.0/8", "an address block (/8, /16 or /24); ip:10.1.* also works"],
  ["severity:>=high", "high and critical (also <=, > and <)"],
  ["type:authentication_failure -user:root", "leave out what matches with a minus or NOT"],
  ["user:alice OR user:bob", "either may match"],
  ["since:2026-11-01 until:2026-11-02", "a time range; a date alone means the whole day"],
  ["\"invalid user\" host:web01", "quote a phrase; fields: user, ip, host, service, source, type, severity, message"],
];

export default function Events() {
  const [qInput, setQInput] = useState("");
  const [filters, setFilters] = useState({ query: "", source: "", event_type: "", severity: "" });
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState(null);
  const [saving, setSaving] = useState(null);
  const [saveError, setSaveError] = useState(null);

  useEffect(() => {
    const id = setTimeout(() => { setFilters((f) => ({ ...f, query: qInput })); setOffset(0); }, 300);
    return () => clearTimeout(id);
  }, [qInput]);

  const setFilter = (key) => (e) => { setFilters((f) => ({ ...f, [key]: e.target.value })); setOffset(0); };
  const { data, error } = usePolling(() => listEvents({ ...filters, limit: LIMIT, offset }), [filters, offset], 5000);
  const { data: saved, reload: reloadSaved } = usePolling(listSavedSearches, [], 0);
  const savedItems = saved?.items ?? [];
  const current = savedItems.find((s) => s.query === qInput.trim());

  const open = async (id) => setSelected(await getEvent(id));

  async function saveSearch(e) {
    e.preventDefault();
    setSaveError(null);
    try {
      await createSavedSearch(saving, qInput.trim());
      setSaving(null);
      await reloadSaved();
    } catch (err) {
      setSaveError(err.message || String(err));
    }
  }

  async function removeSaved() {
    setSaveError(null);
    try {
      await deleteSavedSearch(current.id);
      await reloadSaved();
    } catch (err) {
      setSaveError(err.message || String(err));
    }
  }

  const exportParams = { ...filters };
  return (
    <>
      <PageHeader title="Event monitoring" subtitle="Live feed of normalised events, with a search language" />
      <ErrorBanner error={error} />
      <div className="toolbar">
        <input type="search" placeholder="Search message, user, IP, host… (try user:admin severity:>=high)"
          value={qInput} onChange={(e) => setQInput(e.target.value)} aria-label="Search events" />
        <select value={filters.source} onChange={setFilter("source")}>
          <option value="">All sources</option>{SOURCES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={filters.event_type} onChange={setFilter("event_type")}>
          <option value="">All categories</option>{EVENT_TYPES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={filters.severity} onChange={setFilter("severity")}>
          <option value="">All severities</option>{SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        {savedItems.length > 0 && (
          <select value="" aria-label="Saved searches" onChange={(e) => e.target.value && setQInput(e.target.value)}>
            <option value="">Saved searches…</option>
            {savedItems.map((s) => <option key={s.id} value={s.query}>{s.name}</option>)}
          </select>
        )}
      </div>
      <div className="toolbar">
        {saving === null ? (
          <>
            {current ? (
              <button onClick={removeSaved} aria-label={`Delete saved search ${current.name}`}>Delete saved search</button>
            ) : (
              <button disabled={!qInput.trim()} onClick={() => setSaving("")}>Save this search…</button>
            )}
            <a className="button" href={exportEventsUrl(exportParams, "csv")} download>Export CSV</a>
            <a className="button" href={exportEventsUrl(exportParams, "json")} download>Export JSON</a>
          </>
        ) : (
          <form className="toolbar" onSubmit={saveSearch} aria-label="Save this search">
            <input required autoFocus maxLength={100} placeholder="Name for this search" aria-label="Name for this search"
              value={saving} onChange={(e) => setSaving(e.target.value)} />
            <button type="submit" className="primary">Save</button>
            <button type="button" onClick={() => { setSaving(null); setSaveError(null); }}>Cancel</button>
          </form>
        )}
        <span className="muted">Exports the events this search matches (up to 10,000).</span>
      </div>
      {saveError && <div className="error" role="alert">{saveError}</div>}
      <details className="card search-help">
        <summary>Search tips</summary>
        <table>
          <tbody>
            {EXAMPLES.map(([example, what]) => (
              <tr key={example}>
                <td><button className="link mono" onClick={() => setQInput(example)} aria-label={`Use ${example}`}>{example}</button></td>
                <td className="muted">{what}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
      <section className="card">
        {data?.items.length ? (
          <>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Source</th><th>User</th><th>IP</th><th>Message</th><th aria-label="Open"></th></tr></thead>
                <tbody>
                  {data.items.map((e) => (
                    <tr key={e.id} {...rowProps(() => open(e.id))}>
                      <td className="mono">{fmtTime(e.timestamp)}</td>
                      <td><SeverityBadge value={e.severity} /></td>
                      <td>{e.event_type}</td>
                      <td>{e.source}</td>
                      <td>{e.username || "-"}</td>
                      <td className="mono">{e.source_ip || "-"}</td>
                      <td className="muted">{e.message.slice(0, 80)}</td>
                      <td className="chevron"><Icon name="chevron-right" /></td>
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
