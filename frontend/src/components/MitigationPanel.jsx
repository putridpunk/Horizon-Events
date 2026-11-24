import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { approveMitigation, dismissMitigation, getAlertMitigation, undoMitigation } from "../services/api.js";

const TITLE = {
  block_ip: (a) => `Block ${a.target} in Windows Firewall`,
  quarantine_file: () => "Move the file to quarantine",
};
const EXPLAIN = {
  block_ip: "Windows will ask for your permission once, then the address can no longer connect to this computer. You can remove the block at any time.",
  quarantine_file: "The file is moved, not deleted, so it cannot run. You can restore it at any time.",
};
const APPROVE = { block_ip: "Approve block", quarantine_file: "Quarantine file" };
const UNDO = { block_ip: "Remove block", quarantine_file: "Restore file" };

/** An action's own controls, by state. `act` runs a request and reloads. */
function Controls({ action, act, busy }) {
  const { id, kind, status } = action;
  if (status === "suggested" || status === "failed") {
    return (
      <div className="actions">
        <button className="primary" disabled={busy} onClick={() => act(approveMitigation, id)}>
          {status === "failed" ? "Try again" : APPROVE[kind]}
        </button>
        <button disabled={busy} onClick={() => act(dismissMitigation, id)}>Dismiss</button>
      </div>
    );
  }
  if (status === "done") {
    return (
      <div className="actions">
        <button disabled={busy} onClick={() => act(undoMitigation, id)}>{UNDO[kind]}</button>
      </div>
    );
  }
  return null;
}

function ActionCard({ action, act, busy }) {
  const title = TITLE[action.kind](action);
  const note = action.status === "suggested" ? EXPLAIN[action.kind] : action.message;
  return (
    <div className="mitigation" data-status={action.status}>
      <div>
        <strong>{title}</strong>
        {action.kind === "quarantine_file" && <div className="muted path">{action.target}</div>}
        <span className={`badge mit-${action.status}`}>{action.status === "done" && action.automatic ? "Done automatically" : LABEL[action.status]}</span>
        {action.expired && <span className="badge mit-failed">Expired: remove it</span>}
      </div>
      {note && <div className="muted" role={action.status === "running" ? "status" : undefined}>{note}</div>}
      <Controls action={action} act={act} busy={busy} />
    </div>
  );
}

const LABEL = {
  suggested: "Waiting for you", running: "In progress", done: "Done", failed: "Did not work", dismissed: "Dismissed",
  undone: "Undone",
};

/** Recommended steps for an alert, plus (in the desktop app) the actions the app can take for you. */
export default function MitigationPanel({ alertId }) {
  const { data, error, reload } = usePolling(() => getAlertMitigation(alertId), [alertId], 2000);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState(null);

  async function act(fn, id) {
    setBusy(true);
    setActionError(null);
    try {
      await fn(id);
      await reload();
    } catch (e) {
      setActionError(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  if (error && !data) return <div className="error">Could not load recommended steps: {error}</div>;
  if (!data) return null;
  const shown = data.actions.filter((a) => a.status !== "dismissed");
  return (
    <section aria-label="Recommended steps">
      <h2>Recommended steps</h2>
      <ol className="steps">
        {data.advice.map((line) => <li key={line}>{line}</li>)}
      </ol>
      {data.enabled && shown.map((a) => <ActionCard key={a.id} action={a} act={act} busy={busy} />)}
      {data.enabled && data.skipped.map((s) => (
        <p key={`${s.kind}|${s.target}`} className="muted">Not suggested ({s.target}): {s.reason}</p>
      ))}
      {actionError && <div className="error" role="alert">{actionError}</div>}
    </section>
  );
}
