import { useState } from "react";
import usePolling from "../services/usePolling.js";
import { getModelStatus, trainModel } from "../services/api.js";
import { fmtTime } from "../services/constants.js";
import { ErrorBanner } from "./common.jsx";

export default function ModelCard({ onTrained }) {
  const { data: status, error, reload } = usePolling(getModelStatus, []);
  const [busy, setBusy] = useState(false);
  const [trainError, setTrainError] = useState(null);

  async function train(source) {
    setBusy(true);
    setTrainError(null);
    try {
      await trainModel(source);
      await reload();
      onTrained?.();
    } catch (e) {
      setTrainError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" style={{ marginTop: 16 }}>
      <h2>Anomaly model (HZ-007)</h2>
      <ErrorBanner error={error} />
      {status && (
        <p className="muted">
          {status.trained
            ? `Trained ${fmtTime(status.trained_at)} on ${status.windows} per-IP hourly windows (${status.source}). `
            : "No model trained yet: anomaly detection is inactive. "}
          Features: {status.features.join(", ")}.
        </p>
      )}
      <div className="actions">
        <button className="primary" disabled={busy} onClick={() => train("synthetic")}>
          Train on synthetic baseline
        </button>
        <button disabled={busy} onClick={() => train("database")}>Train on my data</button>
      </div>
      {trainError && <div className="error">{trainError}</div>}
    </section>
  );
}
