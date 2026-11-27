import { Link, useLocation } from "react-router-dom";
import usePolling from "../../services/usePolling.js";
import { getUpdateStatus } from "../../services/api.js";
import { useAuth } from "../../auth/AuthGate.jsx";
import ThemeToggle from "../../theme/ThemeToggle.jsx";
import ImportButton from "../ImportButton.jsx";
import { locate } from "./routes.js";
import useCollectionState from "./useCollectionState.js";

export default function TopBar() {
  const { pathname } = useLocation();
  const { group, title } = locate(pathname);
  const state = useCollectionState();
  const { enabled, user, signOut } = useAuth();
  const update = usePolling(getUpdateStatus, [], 0).data;  // only administrators may ask; for others it is simply absent
  const hint = state.active
    ? `Events are being collected (${state.collecting} system log source${state.collecting === 1 ? "" : "s"}${
      state.watching ? ", watch folder" : ""}).`
    : "Nothing is feeding events in right now. Turn on system logs under Data sources, or import a file.";
  return (
    <header className="appbar" role="banner">
      <div className="appbar-title">
        {group && <><span className="muted">{group}</span><span className="muted"> / </span></>}
        {title}
      </div>
      <div className="appbar-actions">
        <span className={`live${state.active ? " on" : ""}`} data-testid="live-indicator" title={hint}>
          {state.active ? "Collecting" : "Not collecting"}
        </span>
        {update?.update_available && (
          <Link className="update-badge" to="/settings" title={`Version ${update.latest} is available`}>Update available</Link>
        )}
        <ThemeToggle />
        {enabled && user && (
          <span className="who">{user.username} ({user.role}) <button className="link" onClick={signOut}>Sign out</button></span>
        )}
        <ImportButton />
      </div>
    </header>
  );
}
