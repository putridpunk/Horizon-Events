import { useLocation } from "react-router-dom";
import ThemeToggle from "../../theme/ThemeToggle.jsx";
import ImportButton from "../ImportButton.jsx";
import { locate } from "./routes.js";
import useCollectionState from "./useCollectionState.js";

export default function TopBar() {
  const { pathname } = useLocation();
  const { group, title } = locate(pathname);
  const state = useCollectionState();
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
        <ThemeToggle />
        <ImportButton />
      </div>
    </header>
  );
}
