import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { getIntelStatus, refreshIntel } from "../services/api.js";
import { fmtTime } from "../services/constants.js";
import { ErrorBanner } from "./common.jsx";

export default function IntelCard() {
  const { data, error, reload } = usePolling(getIntelStatus, []);
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState(null);
  const [refreshError, setRefreshError] = useState(null);

  async function refresh() {
    setBusy(true);
    setRefreshError(null);
    try {
      const r = await refreshIntel();
      setResults(r.results);
      await reload();
    } catch (e) {
      setRefreshError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" style={{ marginTop: 16 }}>
      <h2>Threat intelligence feeds</h2>
      <ErrorBanner error={error} />
      <p className="muted">
        Alert IPs are checked locally against these lists. Refreshing downloads the public feeds from
        abuse.ch and spamhaus.org; no log data is sent. Each feed can be refreshed once an hour.
      </p>
      {data?.feeds.length ? (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Feed</th><th>Source</th><th>Entries</th><th>Last refreshed</th></tr></thead>
            <tbody>
              {data.feeds.map((f) => (
                <tr key={f.id}>
                  <td>{f.name}<div className="muted">{f.description}</div></td>
                  <td>{f.source}</td><td>{f.entries}</td>
                  <td className="muted">{f.fetched_at ? fmtTime(f.fetched_at) : "bundled"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted">No feeds loaded yet. Refresh to download them.</p>
      )}
      <div className="actions">
        <button className="primary" disabled={busy} onClick={refresh}>{busy ? "Downloading…" : "Refresh feeds"}</button>
      </div>
      {refreshError && <div className="error">{refreshError}</div>}
      {results && results.map((r) => (
        <div key={r.feed} className={r.status === "error" ? "error" : "muted"}>{r.feed}: {r.status} · {r.message}</div>
      ))}
    </section>
  );
}
