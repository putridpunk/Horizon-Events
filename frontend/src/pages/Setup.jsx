import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import usePolling from "../services/usePolling.js";
import { completeSetup, getCollectors, updateCollector } from "../services/api.js";
import { EmptyState, ErrorBanner, PageHeader } from "../components/common.jsx";
import SourceRow from "../components/SourceRow.jsx";

export default function Setup() {
  const navigate = useNavigate();
  const { data, error, reload } = usePolling(getCollectors, [], 3000);
  const [selected, setSelected] = useState(null);
  const [backfill, setBackfill] = useState(false);
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState(null);

  useEffect(() => {  // preselect every source that exists on this computer, once
    if (data && selected === null) {
      setSelected(Object.fromEntries(data.items.map((i) => [i.id, i.access !== "unavailable"])));
    }
  }, [data, selected]);

  async function finish(enable) {
    setBusy(true);
    setSaveError(null);
    try {
      if (enable) {
        for (const item of data.items) {
          if (selected?.[item.id]) await updateCollector(item.id, { enabled: true, backfill_hours: backfill ? 24 : 0 });
        }
      }
      await completeSetup();
      navigate("/", { replace: true });
    } catch (e) {
      setSaveError(e.message);
      setBusy(false);
    }
  }

  const items = data?.items ?? [];
  return (
    <>
      <PageHeader title="Set up system log collection" subtitle="Choose which logs of this computer Horizon Events should watch" />
      <ErrorBanner error={error} />
      <section className="card">
        <p>
          Horizon Events can read this computer&apos;s own event logs and look for suspicious activity, so you never
          have to attach log files. <strong>Everything stays on this machine</strong>: nothing is uploaded, and no
          account is needed. Only a short list of security-relevant events is read, starting from now.
        </p>
        {data && !data.enabled ? (
          <EmptyState>System log collection is not available in this mode.</EmptyState>
        ) : items.length === 0 && data ? (
          <EmptyState>No readable system logs were found on this computer. You can still import log files.</EmptyState>
        ) : (
          <div className="source-list">
            {items.map((item) => (
              <SourceRow key={item.id} item={item} checked={Boolean(selected?.[item.id])} busy={busy}
                onToggle={(on) => setSelected((s) => ({ ...s, [item.id]: on }))} onAccessRequested={reload} />
            ))}
          </div>
        )}
        <label className="source-backfill">
          <input type="checkbox" checked={backfill} onChange={(e) => setBackfill(e.target.checked)} />
          Also read the last 24 hours, to see what has already happened
        </label>
        {saveError && <div className="error" role="alert">{saveError}</div>}
        <div className="actions">
          <button className="primary" disabled={busy || !data?.enabled} onClick={() => finish(true)}>Start collecting</button>
          <button disabled={busy} onClick={() => finish(false)}>Set up later</button>
        </div>
      </section>
    </>
  );
}
