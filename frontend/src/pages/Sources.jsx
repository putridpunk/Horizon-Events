import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { checkCollector, getCollectors, updateCollector } from "../services/api.js";
import { EmptyState, ErrorBanner, PageHeader } from "../components/common.jsx";
import LiveCard from "../components/LiveCard.jsx";
import SourceRow from "../components/SourceRow.jsx";

export default function Sources() {
  const { data, error, reload } = usePolling(getCollectors, [], 3000);
  const [busyId, setBusyId] = useState(null);
  const [actionError, setActionError] = useState(null);

  async function act(id, fn) {
    setBusyId(id);
    setActionError(null);
    try {
      await fn();
      await reload();
    } catch (e) {
      setActionError(e.message);
    } finally {
      setBusyId(null);
    }
  }

  const items = data?.items ?? [];
  return (
    <>
      <PageHeader title="Data sources" subtitle="Where Horizon Events gets its events from" />
      <ErrorBanner error={error} />
      {actionError && <div className="error" role="alert">{actionError}</div>}
      <section className="card">
        <h2>System logs on this computer</h2>
        {data && !data.enabled ? (
          <EmptyState>System log collection is not available in this mode. Import files or use a watch folder below.</EmptyState>
        ) : items.length === 0 && data ? (
          <EmptyState>No readable system logs were found on this computer.</EmptyState>
        ) : (
          <div className="source-list">
            {items.map((item) => (
              <SourceRow key={item.id} item={item} showDetails checked={item.enabled} busy={busyId === item.id}
                onToggle={(on) => act(item.id, () => updateCollector(item.id, { enabled: on }))}
                onCheck={() => act(item.id, () => checkCollector(item.id))} onAccessRequested={reload} />
            ))}
          </div>
        )}
      </section>
      <details className="card">
        <summary><strong>Advanced: watch folder and file import</strong></summary>
        <p className="muted">
          Files placed in the watch folder are read continuously, and any log file can be imported with
          <strong> Import logs</strong>. Use these for logs from other machines or applications.
        </p>
        <LiveCard />
      </details>
    </>
  );
}
