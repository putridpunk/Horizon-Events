import { SeverityBadge } from "../common.jsx";
import Time from "../ui/Time.jsx";

/** What a rule would have flagged over the chosen period. Nothing here was saved. */
export default function ReplayResult({ result }) {
  const sev = result.by_severity ?? {};
  return (
    <section className="replay" aria-label="Test result">
      <p>
        <strong>{result.would_alert}</strong> {result.would_alert === 1 ? "alert" : "alerts"} would have been raised from{" "}
        {result.events_scanned} events in the last {result.days} {result.days === 1 ? "day" : "days"}
        {result.already_alerted > 0 && <> ({result.already_alerted} already {result.already_alerted === 1 ? "has" : "have"} an alert)</>}.
        {result.truncated && " Only the newest events were examined."}
      </p>
      {result.would_alert > 0 && (
        <p className="muted">
          {["critical", "high", "medium", "low"].filter((s) => sev[s]).map((s) => `${sev[s]} ${s}`).join(" · ")}
          {result.top_sources?.length > 0 && <> · most active: {result.top_sources.map((t) => `${t.value} (${t.count})`).join(", ")}</>}
        </p>
      )}
      {result.detections.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Severity</th><th>What</th><th>Source</th><th>Account</th><th>Count</th><th>Last event</th></tr></thead>
            <tbody>
              {result.detections.map((d) => (
                <tr key={d.key}>
                  <td><SeverityBadge value={d.severity} /></td>
                  <td>{d.description}{d.already_alerted && <span className="muted"> (already alerted)</span>}</td>
                  <td className="mono">{d.source_ip || "-"}</td>
                  <td>{d.username || "-"}</td>
                  <td>{d.occurrences}</td>
                  <td>{d.last_event ? <Time value={d.last_event} /> : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {result.would_alert > result.shown && <p className="muted">Showing the first {result.shown}.</p>}
      <p className="muted">{result.note}</p>
    </section>
  );
}
