import { useState } from "react";
import usePolling from "../../services/usePolling.js";
import { createUser, deleteUser, getAudit, listUsers, updateUser } from "../../services/api.js";
import { useAuth } from "../../auth/AuthGate.jsx";
import { ErrorBanner } from "../common.jsx";
import Time from "../ui/Time.jsx";

const ROLE_HELP = {
  viewer: "can look at everything except settings",
  analyst: "can also work on alerts and incidents, import logs and save searches",
  admin: "can do everything, including users, rules and settings",
};

/** People who may sign in, and what they may do. Administrators only. */
export default function UsersCard() {
  const { enabled, user: me } = useAuth();
  const users = usePolling(listUsers, [], 0);
  const audit = usePolling(getAudit, [], 0);
  const [form, setForm] = useState({ username: "", password: "", role: "viewer" });
  const [reset, setReset] = useState(null); // {id, password}
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);

  if (!enabled || me?.role !== "admin") return null;

  async function run(action, done) {
    setBusy(true);
    setMessage(null);
    try {
      await action();
      await Promise.all([users.reload(), audit.reload()]);
      done?.();
    } catch (e) {
      setMessage(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  const items = users.data?.items ?? [];
  const roles = users.data?.roles ?? ["viewer", "analyst", "admin"];
  return (
    <section className="card">
      <h2>People</h2>
      <p className="muted">
        {roles.map((r) => `${r} ${ROLE_HELP[r] ?? ""}`).join("; ")}. Five wrong passwords lock an account for 15 minutes.
      </p>
      <ErrorBanner error={users.error} />
      {message && <div className="error" role="alert">{message}</div>}
      <div className="table-wrap">
        <table>
          <thead><tr><th>User</th><th>Role</th><th>Last sign-in</th><th /></tr></thead>
          <tbody>
            {items.map((u) => (
              <tr key={u.id}>
                <td>{u.username}{u.username === me.username && " (you)"}
                  {u.disabled && <span className="muted"> (disabled)</span>}{u.locked && <span className="sla-late"> (locked)</span>}</td>
                <td>
                  <select value={u.role} disabled={busy} aria-label={`Role of ${u.username}`}
                    onChange={(e) => run(() => updateUser(u.id, { role: e.target.value }))}>
                    {roles.map((r) => <option key={r} value={r}>{r}</option>)}
                  </select>
                </td>
                <td>{u.last_login ? <Time value={u.last_login} /> : "never"}</td>
                <td className="actions">
                  <button disabled={busy} onClick={() => setReset({ id: u.id, name: u.username, password: "" })}
                    aria-label={`Reset password of ${u.username}`}>Reset password</button>
                  {u.locked && <button disabled={busy} onClick={() => run(() => updateUser(u.id, { unlock: true }))}
                    aria-label={`Unlock ${u.username}`}>Unlock</button>}
                  <button disabled={busy || u.username === me.username}
                    onClick={() => run(() => updateUser(u.id, { disabled: !u.disabled }))}
                    aria-label={`${u.disabled ? "Enable" : "Disable"} ${u.username}`}>{u.disabled ? "Enable" : "Disable"}</button>
                  <button disabled={busy || u.username === me.username} onClick={() => run(() => deleteUser(u.id))}
                    aria-label={`Delete ${u.username}`}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {reset && (
        <form className="settings-form" aria-label={`New password for ${reset.name}`}
          onSubmit={(e) => { e.preventDefault(); run(() => updateUser(reset.id, { password: reset.password }), () => setReset(null)); }}>
          <label>New password for {reset.name} (at least 12 characters)
            <input type="password" autoComplete="new-password" value={reset.password}
              onChange={(e) => setReset({ ...reset, password: e.target.value })} />
          </label>
          <p className="muted">They are signed out everywhere and must use the new password.</p>
          <div className="actions">
            <button type="submit" className="primary" disabled={busy || !reset.password}>Set password</button>
            <button type="button" onClick={() => setReset(null)}>Cancel</button>
          </div>
        </form>
      )}
      <h3>Add a person</h3>
      <form className="settings-form" aria-label="Add a person"
        onSubmit={(e) => { e.preventDefault(); run(() => createUser(form), () => setForm({ username: "", password: "", role: "viewer" })); }}>
        <label>User name<input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} autoComplete="off" /></label>
        <label>Password (at least 12 characters)<input type="password" value={form.password} autoComplete="new-password"
          onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
        <label>Role
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{roles.map((r) => <option key={r} value={r}>{r}</option>)}</select>
        </label>
        <div className="actions"><button type="submit" disabled={busy || !form.username || !form.password}>Add person</button></div>
      </form>
      <details>
        <summary>Recent sign-ins and changes</summary>
        <div className="table-wrap">
          <table>
            <thead><tr><th>When</th><th>Who</th><th>What</th><th>Address</th></tr></thead>
            <tbody>
              {(audit.data?.items ?? []).map((a) => (
                <tr key={a.id}><td><Time value={a.at} /></td><td>{a.actor ?? "-"}</td><td>{a.action}{a.detail ? ` · ${a.detail}` : ""}</td><td className="mono">{a.ip ?? "-"}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  );
}
