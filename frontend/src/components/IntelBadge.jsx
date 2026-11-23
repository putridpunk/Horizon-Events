/** Shows when an alert's IP appears on a downloaded threat feed (matched locally). */
export default function IntelBadge({ intel }) {
  if (!intel?.listed) return null;
  const names = intel.feeds.map((f) => f.name).join(", ");
  return (
    <span className="badge critical" title={`Listed on: ${names}`} style={{ marginLeft: 6 }}>
      Known malicious
    </span>
  );
}
