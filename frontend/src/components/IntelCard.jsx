import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { deleteIntelList, getIntelStatus, importIntelList, refreshIntel } from "../services/api.js";
import { fmtTime } from "../services/constants.js";
import { ErrorBanner } from "./common.jsx";

export default function IntelCard() {
  const { data, error, reload } = usePolling(getIntelStatus, []);
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState(null);
  const [refreshError, setRefreshError] = useState(null);
  const [listName, setListName] = useState("");
  const [file, setFile] = useState(null);
  const [importMessage, setImportMessage] = useState(null);

  async function importList(e) {
    e.preventDefault();
    setBusy(true);
    setImportMessage(null);
    try {
      const r = await importIntelList(file, listName);
      setImportMessage({ text: `${r.replaced ? "Replaced" : "Imported"} "${r.name}": ${r.ips} addresses, ${r.hashes} file hashes, ${r.domains} domains${r.skipped ? `, ${r.skipped} lines skipped` : ""}.` });
      setListName("");
      setFile(null);
      await reload();
    } catch (err) {
      setImportMessage({ error: true, text: err.message || String(err) });
    } finally {
      setBusy(false);
    }
  }

  async function removeList(f) {
    setBusy(true);
    setImportMessage(null);
    try {
      await deleteIntelList(f.id);
      await reload();
    } catch (err) {
      setImportMessage({ error: true, text: err.message || String(err) });
    } finally {
      setBusy(false);
    }
  }

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
            <thead><tr><th>Feed</th><th>Source</th><th>Entries</th><th>Last refreshed</th><th aria-label="Actions" /></tr></thead>
            <tbody>
              {data.feeds.map((f) => (
                <tr key={f.id}>
                  <td>{f.name}<div className="muted">{f.description}</div></td>
                  <td>{f.source}</td><td>{f.entries}</td>
                  <td className="muted">{f.fetched_at ? fmtTime(f.fetched_at) : "bundled"}</td>
                  <td>{f.source === "custom" && (
                    <button disabled={busy} onClick={() => removeList(f)} aria-label={`Remove list ${f.name}`}>Remove</button>
                  )}</td>
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
      <h3>Import your own list</h3>
      <p className="muted">
        Add bad IP addresses, file hashes and domain names from a STIX 2.1 bundle (.json), a MISP export (.json) or a
        text file with one indicator per line. The file is read here and never uploaded anywhere. Alerts then show a match
        for their IP address, for the file hash of a malware detection, and for domains in their events. Importing a
        list with the same name replaces it.
      </p>
      <form className="settings-form" onSubmit={importList} aria-label="Import a list">
        <label>List name<input required maxLength={100} value={listName} onChange={(e) => setListName(e.target.value)} /></label>
        <label>File<input type="file" accept=".json,.txt,.csv,.stix,.misp"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>
        <div className="actions"><button type="submit" disabled={busy || !file || !listName.trim()}>Import list</button></div>
      </form>
      {importMessage && <div className={importMessage.error ? "error" : "muted"} role="alert">{importMessage.text}</div>}
      {results && results.map((r) => (
        <div key={r.feed} className={r.status === "error" ? "error" : "muted"}>{r.feed}: {r.status} · {r.message}</div>
      ))}
    </section>
  );
}
