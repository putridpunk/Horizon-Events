import { useState } from "react";
import { Link } from "react-router-dom";
import usePolling from "../services/usePolling.js";
import { getScanStatus, listScans, startScan } from "../services/api.js";
import { hasPicker, pickFiles, pickFolder } from "../services/desktop.js";
import { EmptyState, ErrorBanner, PageHeader } from "../components/common.jsx";
import Icon from "../components/ui/Icon.jsx";
import Time from "../components/ui/Time.jsx";

const RESULT = {
  clean: ["Clean", "check"],
  threat: ["Threat found", "alert"],
  error: ["Could not scan", "minus"],
};

function ResultBadge({ value }) {
  const [text, icon] = RESULT[value] ?? [value, "minus"];
  return <span className={`badge ${value}`}><Icon name={icon} size={14} />{text}</span>;
}

function summary(scan) {
  if (scan.status === "running") return `Scanning ${Math.min(scan.done + 1, scan.total)} of ${scan.total}…`;
  if (scan.status === "failed") return `The scan stopped: ${scan.error ?? "unknown error"}`;
  if (scan.threats) return `${scan.threats} ${scan.threats === 1 ? "threat" : "threats"} found`;
  const failed = scan.results.filter((r) => r.status === "error").length;
  return failed ? `No threats found, ${failed} ${failed === 1 ? "item" : "items"} could not be scanned` : "No threats found";
}

function LatestScan({ scan }) {
  return (
    <section className="card" aria-label="Latest scan">
      <div className="card-header">
        <h2>Latest scan</h2>
        <span className="muted"><Time value={scan.created_at} /></span>
      </div>
      <p role="status"><strong>{summary(scan)}</strong></p>
      {scan.threats > 0 && (
        <p>Each threat was raised as a critical alert. <Link to="/alerts">View alerts</Link></p>
      )}
      <div className="table-wrap">
        <table>
          <thead><tr><th>Item</th><th>Result</th><th>Details</th></tr></thead>
          <tbody>
            {scan.targets.map((path) => {
              const result = scan.results.find((r) => r.path === path);
              return (
                <tr key={path}>
                  <td className="path">{path}</td>
                  <td>{result ? <ResultBadge value={result.status} /> : <span className="muted">Waiting…</span>}</td>
                  <td>
                    {result?.threats.map((t) => (
                      <div key={`${t.path}|${t.threat}`}>
                        <strong>{t.threat}</strong>
                        {t.path !== path && <div className="muted path">{t.path}</div>}
                      </div>
                    ))}
                    {result?.status === "error" && <span>{result.message}</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default function Scan() {
  const status = usePolling(getScanStatus, [], 0);
  const scans = usePolling(listScans, [], 1500);
  const [error, setError] = useState(null);
  const [starting, setStarting] = useState(false);

  const items = scans.data?.items ?? [];
  const latest = items[0];
  const running = starting || latest?.status === "running";
  const info = status.data;

  async function choose(picker) {
    setError(null);
    if (!hasPicker()) {
      setError("The file picker is not available here. Open Horizon Events from its desktop window.");
      return;
    }
    setStarting(true);
    try {
      const paths = await picker();
      if (paths.length) {
        await startScan(paths);
        await scans.reload();
      }
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setStarting(false);
    }
  }

  return (
    <>
      <PageHeader title="Scan files" subtitle="Check files and folders for malware" />
      <ErrorBanner error={status.error || scans.error} />
      {error && <div className="error" role="alert">{error}</div>}
      <section className="card">
        <h2>Choose what to scan</h2>
        {info && !info.enabled ? (
          <EmptyState>{info.message}</EmptyState>
        ) : (
          <>
            <p className="muted">
              Files are scanned where they are, using Microsoft Defender on this computer. Nothing is uploaded, moved
              or deleted. Each threat found becomes a critical alert.
            </p>
            {info && !info.available && <div className="error" role="alert">{info.message}</div>}
            <div className="actions">
              <button className="primary" disabled={!info?.available || running} onClick={() => choose(pickFiles)}>
                <Icon name="file" />Choose files…
              </button>
              <button disabled={!info?.available || running} onClick={() => choose(pickFolder)}>
                <Icon name="folders" />Choose folder…
              </button>
            </div>
          </>
        )}
      </section>
      {latest && <LatestScan scan={latest} />}
      {items.length > 1 && (
        <section className="card">
          <h2>Earlier scans</h2>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Started</th><th>Items</th><th>Outcome</th></tr></thead>
              <tbody>
                {items.slice(1).map((s) => (
                  <tr key={s.id}><td><Time value={s.created_at} /></td><td>{s.total}</td><td>{summary(s)}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </>
  );
}
