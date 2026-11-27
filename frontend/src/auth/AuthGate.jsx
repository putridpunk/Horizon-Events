import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { getAuthStatus, login, logout, setupAdmin } from "../services/api.js";

const AuthContext = createContext({ enabled: false, user: null, signOut: async () => {} });

/** Who is signed in, when sign-in is turned on for this server. Without it, everything is open as before. */
export const useAuth = () => useContext(AuthContext);

function Frame({ title, children }) {
  return (
    <main className="auth-page">
      <section className="card auth-card">
        <h1>Horizon Events</h1>
        <h2>{title}</h2>
        {children}
      </section>
    </main>
  );
}

function LoginForm({ onDone }) {
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(name, password);
      setPassword("");
      await onDone();
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Frame title="Sign in">
      <form className="settings-form" onSubmit={submit} aria-label="Sign in">
        <label>User name<input autoFocus autoComplete="username" value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label>Password<input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        {error && <div className="error" role="alert">{error}</div>}
        <div className="actions"><button className="primary" type="submit" disabled={busy || !name || !password}>Sign in</button></div>
      </form>
    </Frame>
  );
}

function SetupForm({ onDone }) {
  const [form, setForm] = useState({ token: "", username: "", password: "" });
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const set = (key) => (e) => setForm((f) => ({ ...f, [key]: e.target.value }));

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await setupAdmin(form.token, form.username, form.password);
      await onDone();
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Frame title="Create the first administrator">
      <p className="muted">
        Sign-in is turned on and nobody has an account yet. Enter the setup code that the server wrote to its log when it
        started, then choose a user name and a password of at least 12 characters.
      </p>
      <form className="settings-form" onSubmit={submit} aria-label="Create the first administrator">
        <label>Setup code<input autoComplete="off" value={form.token} onChange={set("token")} /></label>
        <label>User name<input autoComplete="username" value={form.username} onChange={set("username")} /></label>
        <label>Password<input type="password" autoComplete="new-password" value={form.password} onChange={set("password")} /></label>
        {error && <div className="error" role="alert">{error}</div>}
        <div className="actions"><button className="primary" type="submit" disabled={busy || !form.token || !form.username || !form.password}>Create administrator</button></div>
      </form>
    </Frame>
  );
}

export default function AuthGate({ children }) {
  const [status, setStatus] = useState(null);
  const [error, setError] = useState(null);

  const refresh = useCallback(async () => {
    try {
      setStatus(await getAuthStatus());
      setError(null);
    } catch (e) {
      setError(e.message || String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
    window.addEventListener("horizon-auth-required", refresh);
    return () => window.removeEventListener("horizon-auth-required", refresh);
  }, [refresh]);

  const signOut = useCallback(async () => {
    try { await logout(); } finally { await refresh(); }
  }, [refresh]);

  if (error) return <Frame title="Cannot reach the server"><div className="error" role="alert">{error}</div></Frame>;
  if (!status) return null;
  if (status.enabled && status.setup_required) return <SetupForm onDone={refresh} />;
  if (status.enabled && !status.user) return <LoginForm onDone={refresh} />;
  return <AuthContext.Provider value={{ enabled: !!status.enabled, user: status.user, signOut }}>{children}</AuthContext.Provider>;
}
