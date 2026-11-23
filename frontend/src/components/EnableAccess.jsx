import { useState } from "react";
import { enableSecurityAccess } from "../services/api.js";
import { Modal } from "./overlay.jsx";

/** The one-time "let Horizon Events read the Windows Security log" step, with an explicit confirmation. */
export default function EnableAccess({ onRequested }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);

  async function confirm() {
    setBusy(true);
    setError(null);
    try {
      const r = await enableSecurityAccess();
      setOpen(false);
      setMessage(
        r.requested
          ? "Windows asked for your permission. Once you approve it, sign out of Windows and back in one time; Horizon Events then starts reading the Security log by itself."
          : "The request was not approved, so nothing was changed. You can try again whenever you like.",
      );
      onRequested?.(r);
    } catch (e) {
      setError(e.message);
      setOpen(false);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <button className="primary" onClick={() => { setMessage(null); setError(null); setOpen(true); }}>
        Enable access
      </button>
      {message && <p className="muted" role="status">{message}</p>}
      {error && <div className="error" role="alert">{error}</div>}
      {open && (
        <Modal title="Allow Horizon Events to read the Security log?" busy={busy} onClose={() => setOpen(false)}>
          <p>
            Windows keeps sign-in activity (failed logons, account lockouts, new accounts) in a protected log.
            To read it, your account must be a member of the built-in <strong>Event Log Readers</strong> group.
          </p>
          <p>
            Choosing <strong>Continue</strong> asks Windows to add you to that group. Windows will show its own
            permission prompt, and nothing changes unless you approve it. Afterwards, sign out of Windows and
            back in once. You can remove yourself from the group at any time in Computer Management.
          </p>
          <div className="actions">
            <button className="primary" disabled={busy} onClick={confirm}>Continue</button>
            <button disabled={busy} onClick={() => setOpen(false)}>Cancel</button>
          </div>
        </Modal>
      )}
    </div>
  );
}
