/** MITRE ATT&CK technique badges linking to attack.mitre.org. Low-confidence mappings are dimmed. */
export default function TechniqueBadges({ techniques = [] }) {
  if (!techniques.length) return null;
  return (
    <div>
      {techniques.map((t) => (
        <a
          key={t.id}
          className={`badge technique ${t.confidence === "low" ? "low" : ""}`}
          href={t.url}
          target="_blank"
          rel="noopener noreferrer"
          title={`${t.name} · ${t.tactics.join(", ")}${t.confidence === "low" ? " · low-confidence mapping" : ""}`}
          onClick={(e) => e.stopPropagation()}
        >
          {t.id}
        </a>
      ))}
    </div>
  );
}
