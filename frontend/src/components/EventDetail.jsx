import { fmtTime } from "../services/constants.js";
import { SeverityBadge } from "./common.jsx";
import { Modal } from "./overlay.jsx";

export default function EventDetail({ event, onClose }) {
  if (!event) return null;
  const rows = [
    ["Time", fmtTime(event.timestamp)],
    ["Source", event.source],
    ["Type", event.event_type],
    ["Severity", <SeverityBadge key="s" value={event.severity} />],
    ["User", event.username || "-"],
    ["Source IP", event.source_ip || "-"],
    ["Host", event.host || "-"],
    ["Service", event.service || "-"],
  ];
  return (
    <Modal title={`Event #${event.id}`} onClose={onClose}>
        <dl className="kv">
          {rows.map(([k, v]) => (
            <div key={k} style={{ display: "contents" }}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
        <h2>Message</h2>
        <p>{event.message || "-"}</p>
        <h2>Raw log</h2>
        <pre className="raw">{event.raw}</pre>
        <div className="actions"><button onClick={onClose}>Close</button></div>
    </Modal>
  );
}
