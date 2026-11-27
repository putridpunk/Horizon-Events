import { useState } from "react";
import { changePassword } from "../../services/api.js";
import { useAuth } from "../../auth/AuthGate.jsx";

/** Who you are signed in as, and changing your own password. Shown only when this server asks people to sign in. */
export default function AccountCard() {
  const { enabled, user, signOut } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);

  if (!enabled || !user) return null;

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      await changePassword(current, next);
      setCurrent("");
      setNext("");
      setMessage({ text: "Password changed. Your other sign-ins have been ended." });
    } catch (err) {
      setMessage({ error: true, text: err.message || String(err) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>Your account</h2>
      <p>Signed in as <strong>{user.username}</strong> ({user.role}).</p>
      <form className="settings-form" onSubmit={submit} aria-label="Change your password">
        <label>Current password<input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} /></label>
        <label>New password (at least 12 characters)<input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} /></label>
        <div className="actions">
          <button type="submit" disabled={busy || !current || !next}>Change password</button>
          <button type="button" onClick={signOut}>Sign out</button>
        </div>
      </form>
      {message && <div className={message.error ? "error" : "muted"} role="alert">{message.text}</div>}
    </section>
  );
}
