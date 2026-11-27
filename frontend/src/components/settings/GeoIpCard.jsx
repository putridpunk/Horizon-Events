import { useState } from "react";
import usePolling from "../../services/usePolling.js";
import { getGeoIp, setGeoIp } from "../../services/api.js";
import { hasFileDialogs, pickFile } from "../../services/desktop.js";
import { ErrorBanner } from "../common.jsx";

/** The location database behind the "new country" and "impossible travel" rules. It is never uploaded or looked up online. */
export default function GeoIpCard() {
  const { data, error, reload } = usePolling(getGeoIp, [], 0);
  const [path, setPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);

  async function save(value) {
    setBusy(true);
    setMessage(null);
    try {
      await setGeoIp(value);
      setPath("");
      await reload();
    } catch (e) {
      setMessage(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  async function choose() {
    const picked = await pickFile();
    if (picked) setPath(picked);
  }

  if (!data) return error ? <ErrorBanner error={error} /> : null;
  return (
    <section className="card">
      <h2>Sign-in locations</h2>
      <p className="muted">
        With a location database, Horizon Events can tell when an account signs in from a new country or from two places too
        far apart to travel between. The database is a file you download yourself (for example MaxMind's free GeoLite2 City,
        which needs a free account); addresses are looked up in that file on this computer and never sent anywhere.
        Without it those two rules stay silent.
      </p>
      {data.configured ? (
        <p>
          In use: <span className="mono">{data.path}</span>
          {data.database?.type && <span className="muted"> ({data.database.type})</span>}
        </p>
      ) : (
        <p className="muted">No database is set.</p>
      )}
      {data.error && <div className="error" role="alert">{data.error}</div>}
      {data.from_environment && <p className="muted">The path is set by the HORIZON_GEOIP_DB environment variable.</p>}
      <form className="settings-form" onSubmit={(e) => { e.preventDefault(); save(path.trim()); }} aria-label="Location database">
        <label>Full path of the .mmdb file
          <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="C:\data\GeoLite2-City.mmdb" />
        </label>
        <div className="actions">
          {hasFileDialogs() && <button type="button" disabled={busy} onClick={choose}>Choose file…</button>}
          <button type="submit" className="primary" disabled={busy || !path.trim()}>Use this database</button>
          {data.configured && <button type="button" disabled={busy} onClick={() => save(null)}>Stop using it</button>}
        </div>
      </form>
      {message && <div className="error" role="alert">{message}</div>}
    </section>
  );
}
