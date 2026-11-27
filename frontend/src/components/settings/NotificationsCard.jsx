import { useState } from "react";
import usePolling from "../../services/usePolling.js";
import {
  createNotificationChannel, deleteNotificationChannel, listNotificationChannels, testNotificationChannel,
  updateNotificationChannel,
} from "../../services/api.js";
import { SEVERITIES } from "../../services/constants.js";
import { EmptyState, ErrorBanner } from "../common.jsx";
import Time from "../ui/Time.jsx";

const KIND_LABEL = { webhook: "Webhook", slack: "Slack", discord: "Discord", email: "Email" };
const BLANK = {
  name: "", kind: "slack", min_severity: "high", url: "", secret: "",
  host: "", port: "", security: "starttls", username: "", password: "", from_addr: "", to_addrs: "",
};

function configFor(form) {
  if (form.kind === "email") {
    return {
      host: form.host, port: form.port ? Number(form.port) : undefined, security: form.security,
      username: form.username, password: form.password, from_addr: form.from_addr, to_addrs: form.to_addrs,
    };
  }
  return form.kind === "webhook" ? { url: form.url, secret: form.secret } : { url: form.url };
}

function target(channel) {
  const c = channel.config;
  return channel.kind === "email" ? `${(c.to_addrs ?? []).join(", ")} via ${c.host}` : c.url_host;
}

/** Where new alerts are sent besides this app: a webhook, Slack, Discord or email. */
export default function NotificationsCard() {
  const { data, error, reload } = usePolling(listNotificationChannels, [], 0);
  const [form, setForm] = useState(null);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);

  const set = (key) => (e) => setForm((f) => ({ ...f, [key]: e.target.value }));

  async function run(action, done) {
    setBusy(true);
    setMessage(null);
    try {
      const result = await action();
      await reload();
      done?.(result);
    } catch (e) {
      setMessage({ error: true, text: e.message || String(e) });
    } finally {
      setBusy(false);
    }
  }

  const save = (e) => {
    e.preventDefault();
    return run(
      () => createNotificationChannel({
        name: form.name, kind: form.kind, min_severity: form.min_severity, config: configFor(form),
      }),
      () => setForm(null),
    );
  };
  const test = (c) => run(() => testNotificationChannel(c.id), (r) => setMessage(
    r.ok ? { text: `Test message sent to ${c.name}.` } : { error: true, text: `Test to ${c.name} failed: ${r.error}` }));

  const items = data?.items ?? [];
  return (
    <section className="card">
      <h2>Notifications</h2>
      <p className="muted">
        Send new alerts to a webhook, Slack, Discord or an email address. This is the only way alert details leave this
        computer, and only to the places you add here. Each channel gets alerts at or above the severity you choose.
      </p>
      <ErrorBanner error={error} />
      {message && <div className={message.error ? "error" : "muted"} role="alert">{message.text}</div>}
      {data && items.length === 0 && !form && <EmptyState>No notification channels yet.</EmptyState>}
      {items.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Type</th><th>Sends to</th><th>From severity</th><th>Last sent</th><th /></tr></thead>
            <tbody>
              {items.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}{!c.enabled && <span className="muted"> (off)</span>}</td>
                  <td>{KIND_LABEL[c.kind] ?? c.kind}</td>
                  <td className="mono">{target(c)}</td>
                  <td>{c.min_severity}</td>
                  <td>
                    {c.last_error ? <span className="sla-late">{c.last_error}</span>
                      : c.last_sent ? <Time value={c.last_sent} /> : "-"}
                  </td>
                  <td className="actions">
                    <button disabled={busy} onClick={() => test(c)} aria-label={`Send a test to ${c.name}`}>Send test</button>
                    <button disabled={busy} onClick={() => run(() => updateNotificationChannel(c.id, { enabled: !c.enabled }))}
                      aria-label={`${c.enabled ? "Turn off" : "Turn on"} ${c.name}`}>{c.enabled ? "Turn off" : "Turn on"}</button>
                    <button disabled={busy} onClick={() => run(() => deleteNotificationChannel(c.id))}
                      aria-label={`Remove ${c.name}`}>Remove</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {form ? (
        <form className="settings-form" onSubmit={save} aria-label="Add a notification channel">
          <label>Name<input required value={form.name} onChange={set("name")} maxLength={100} /></label>
          <label>Type
            <select value={form.kind} onChange={set("kind")}>
              {Object.entries(KIND_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
          <label>Send alerts from severity
            <select value={form.min_severity} onChange={set("min_severity")}>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          {form.kind !== "email" ? (
            <>
              <label>Address<input required type="url" value={form.url} onChange={set("url")}
                placeholder={form.kind === "webhook" ? "https://example.com/hook" : "https://..."} /></label>
              {form.kind === "webhook" && (
                <label>Signing secret (optional)<input type="password" autoComplete="off" value={form.secret}
                  onChange={set("secret")} /></label>
              )}
            </>
          ) : (
            <>
              <label>Mail server<input required value={form.host} onChange={set("host")} placeholder="smtp.example.com" /></label>
              <label>Port<input value={form.port} onChange={set("port")} inputMode="numeric" placeholder="587" /></label>
              <label>Connection
                <select value={form.security} onChange={set("security")}>
                  <option value="starttls">STARTTLS</option><option value="ssl">SSL/TLS</option><option value="none">None</option>
                </select>
              </label>
              <label>User name (optional)<input value={form.username} onChange={set("username")} autoComplete="off" /></label>
              <label>Password (optional)<input type="password" value={form.password} onChange={set("password")} autoComplete="off" /></label>
              <label>Send from<input required type="email" value={form.from_addr} onChange={set("from_addr")} /></label>
              <label>Send to (separate with commas)<input required value={form.to_addrs} onChange={set("to_addrs")} /></label>
            </>
          )}
          <div className="actions">
            <button type="submit" className="primary" disabled={busy}>Add channel</button>
            <button type="button" disabled={busy} onClick={() => setForm(null)}>Cancel</button>
          </div>
        </form>
      ) : (
        <p><button onClick={() => setForm({ ...BLANK })}>Add a channel…</button></p>
      )}
    </section>
  );
}
