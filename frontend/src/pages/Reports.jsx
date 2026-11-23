import { useState } from "react";
import { getReport, reportUrl } from "../services/api.js";
import { EmptyState, ErrorBanner, PageHeader, StatCard } from "../components/common.jsx";

const today = () => new Date().toISOString().slice(0, 10);
const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10);

export default function Reports() {
  const [start, setStart] = useState(daysAgo(30));
  const [end, setEnd] = useState(today());
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);

  // The end date is inclusive: send the start of the following day.
  const endExclusive = () => new Date(new Date(end).getTime() + 86400000).toISOString().slice(0, 10);

  async function preview() {
    setError(null);
    try { setReport(await getReport(start, endExclusive())); } catch (e) { setError(e.message); }
  }

  return (
    <>
      <PageHeader title="Reports" subtitle="Summarise security activity for a period and export it" />
      <ErrorBanner error={error} />
      <div className="toolbar">
        <label>From <input type="date" value={start} onChange={(e) => setStart(e.target.value)} /></label>
        <label>To <input type="date" value={end} onChange={(e) => setEnd(e.target.value)} /></label>
        <button className="primary" onClick={preview}>Generate</button>
        {["json", "csv", "html"].map((f) => (
          <a key={f} href={reportUrl(start, endExclusive(), f)}><button>Download {f.toUpperCase()}</button></a>
        ))}
      </div>
      {report ? (
        <>
          <div className="grid cols-4" style={{ marginBottom: 16 }}>
            <StatCard label="Events processed" value={report.total_events} tone="accent" />
            <StatCard label="Alerts generated" value={report.total_alerts} />
            <StatCard label="First event" value={report.first_event ? report.first_event.slice(0, 10) : "-"} />
            <StatCard label="Last event" value={report.last_event ? report.last_event.slice(0, 10) : "-"} />
          </div>
          <div className="grid cols-2">
            <section className="card">
              <h2>Event categories</h2>
              {report.top_event_types.map((t) => <div key={t.name} className="bar-row"><span className="name">{t.name}</span><span>{t.count}</span></div>)}
            </section>
            <section className="card">
              <h2>MITRE ATT&amp;CK techniques</h2>
              {report.techniques.filter((t) => t.alerts > 0).length ? (
                report.techniques.filter((t) => t.alerts > 0).map((t) => (
                  <div key={t.id} className="bar-row"><span className="name">{t.id} {t.name}</span><span>{t.alerts}</span></div>
                ))
              ) : (
                <EmptyState>No alerts mapped to techniques in this period.</EmptyState>
              )}
            </section>
            <section className="card">
              <h2>Alert severity</h2>
              {report.severity_distribution.map((s) => <div key={s.severity} className="bar-row"><span className="name">{s.severity}</span><span>{s.count}</span></div>)}
            </section>
            <section className="card">
              <h2>Incidents ({report.incidents.total})</h2>
              {Object.entries(report.incidents.by_status).map(([status, n]) => (
                <div key={status} className="bar-row"><span className="name">{status}</span><span>{n}</span></div>
              ))}
            </section>
          </div>
        </>
      ) : (
        <section className="card"><EmptyState>Choose a period and click Generate to preview a report.</EmptyState></section>
      )}
    </>
  );
}
