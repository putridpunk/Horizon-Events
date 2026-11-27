import usePolling from "../services/usePolling.js";
import { getSyslogStatus } from "../services/api.js";
import Time from "./ui/Time.jsx";

/** Status of the optional network syslog receiver (started with HORIZON_SYSLOG_PORT). */
export default function SyslogCard() {
  const { data } = usePolling(getSyslogStatus, [], 5000);
  if (!data) return null;
  return (
    <section className="card">
      <h2>Network syslog</h2>
      {!data.enabled ? (
        <p className="muted">
          Off. Set <span className="mono">HORIZON_SYSLOG_PORT</span> (for example 5514) before starting the server to receive
          syslog from other machines over UDP and TCP. It listens on this computer only unless
          <span className="mono"> HORIZON_SYSLOG_BIND</span> says otherwise.
        </p>
      ) : (
        <>
          <p className="muted">
            Listening on <span className="mono">{data.bind}:{data.port}</span> (UDP and TCP). Anything that can reach this
            port can add events, so only expose it to networks you trust.
          </p>
          <dl className="kv">
            <dt>Received</dt><dd>{data.received}</dd>
            <dt>Stored as events</dt><dd>{data.imported}</dd>
            <dt>Alerts raised</dt><dd>{data.alerts}</dd>
            <dt>Waiting</dt><dd>{data.queued}</dd>
            <dt>Dropped (flood)</dt><dd>{data.dropped}</dd>
            <dt>Last message</dt><dd>{data.last_message ? <Time value={data.last_message} /> : "-"}</dd>
          </dl>
          {data.last_error && <div className="error">{data.last_error}</div>}
        </>
      )}
    </section>
  );
}
