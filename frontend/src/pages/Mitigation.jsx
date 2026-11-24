import { useEffect, useState } from "react";
import usePolling from "../services/usePolling.js";
import { getMitigationHistory, getMitigationSettings, undoMitigation, updateMitigationSettings } from "../services/api.js";
import { EmptyState, ErrorBanner, PageHeader } from "../components/common.jsx";
import Time from "../components/ui/Time.jsx";

const KIND = { block_ip: "Block address", quarantine_file: "Quarantine file" };
const STATUS = {
  suggested: "Waiting for you", running: "In progress", done: "Done", failed: "Did not work", dismissed: "Dismissed",
  undone: "Undone",
};
const UNDO = { block_ip: "Remove block", quarantine_file: "Restore file" };

function SettingsCard({ settings, onSaved }) {
  const [form, setForm] = useState(null);
  const [message, setMessage] = useState(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (settings && !form) {
      setForm({ ...settings, allowlist: settings.allowlist.join("\n") });
    }
  }, [settings, form]);
  if (!form) return null;

  const set = (key) => (e) => setForm({ ...form, [key]: e.target.type === "checkbox" ? e.target.checked : e.target.value });

  async function save(e) {
    e.preventDefault();
    setSaving(true);
    setMessage(null);
    try {
      await updateMitigationSettings({
        block_ip: form.block_ip, quarantine_file: form.quarantine_file, block_private: form.block_private,
        block_days: Number(form.block_days), allowlist: form.allowlist.split(/\r?\n/).map((l) => l.trim()).filter(Boolean),
      });
      setMessage({ ok: true, text: "Saved." });
      onSaved();
    } catch (err) {
      setMessage({ ok: false, text: err.message || String(err) });
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="card">
      <h2>How Horizon Events responds</h2>
      <p className="muted">
        Every alert always shows recommended steps. These settings control what the app may do on this computer, and
        it never acts without your approval unless you choose Automatic.
      </p>
      <form onSubmit={save} className="settings-form">
        <label>
          Block attacking addresses
          <select value={form.block_ip} onChange={set("block_ip")}>
            <option value="off">Off: only recommend</option>
            <option value="ask">Ask first (Windows will also ask for permission)</option>
          </select>
        </label>
        <label>
          Quarantine malware
          <select value={form.quarantine_file} onChange={set("quarantine_file")}>
            <option value="off">Off: only recommend</option>
            <option value="ask">Ask first</option>
            <option value="auto">Automatic: move it as soon as it is found</option>
          </select>
        </label>
        <label>
          Remind me to remove a block after (days)
          <input type="number" min="1" max="365" value={form.block_days} onChange={set("block_days")} />
        </label>
        <label className="check">
          <input type="checkbox" checked={form.block_private} onChange={set("block_private")} />
          Allow blocking private-network addresses (risky: this can cut off your own router or devices)
        </label>
        <label>
          Never block these addresses (one per line, ranges like 192.168.1.0/24 allowed)
          <textarea rows={3} value={form.allowlist} onChange={set("allowlist")} />
        </label>
        <div className="actions">
          <button className="primary" type="submit" disabled={saving}>Save settings</button>
        </div>
      </form>
      {message && <div className={message.ok ? "import-message" : "error"} role={message.ok ? "status" : "alert"}>{message.text}</div>}
    </section>
  );
}

export default function Mitigation() {
  const settings = usePolling(getMitigationSettings, [], 0);
  const history = usePolling(getMitigationHistory, [], 3000);
  const [error, setError] = useState(null);
  const enabled = settings.data?.enabled;
  const items = history.data?.items ?? [];

  async function undo(id) {
    setError(null);
    try {
      await undoMitigation(id);
      await history.reload();
    } catch (e) {
      setError(e.message || String(e));
    }
  }

  return (
    <>
      <PageHeader title="Mitigation" subtitle="What Horizon Events may do about alerts, and what it has done" />
      <ErrorBanner error={settings.error} />
      {error && <div className="error" role="alert">{error}</div>}
      {settings.data && !enabled ? (
        <section className="card"><EmptyState>Carrying out actions is only available in the desktop app.</EmptyState></section>
      ) : (
        <>
          <SettingsCard settings={settings.data} onSaved={settings.reload} />
          <section className="card">
            <h2>History</h2>
            {items.length === 0 ? (
              <EmptyState>No actions yet. They appear here when you approve a recommended step on an alert.</EmptyState>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>When</th><th>Action</th><th>Target</th><th>Status</th><th /></tr></thead>
                  <tbody>
                    {items.map((m) => (
                      <tr key={m.id}>
                        <td><Time value={m.created_at} /></td>
                        <td>{KIND[m.kind]}{m.automatic ? " (automatic)" : ""}</td>
                        <td className="path">{m.target}</td>
                        <td>
                          {STATUS[m.status]}
                          {m.expired && <strong> · expired</strong>}
                          {m.message && <div className="muted">{m.message}</div>}
                        </td>
                        <td>{m.status === "done" && <button onClick={() => undo(m.id)}>{UNDO[m.kind]}</button>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </>
  );
}
