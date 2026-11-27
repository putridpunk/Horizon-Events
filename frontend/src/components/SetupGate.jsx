import { useEffect, useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import usePolling from "../services/usePolling.js";
import { getSetup } from "../services/api.js";

/** Sent by the setup screen once the choice is saved, so the gate stops sending people back to it. */
export const SETUP_COMPLETED = "horizon-setup-completed";

/** Sends the user to the first-run setup until it has been completed (only when system logs are available). */
export default function SetupGate({ children }) {
  const location = useLocation();
  const { data, loading } = usePolling(getSetup, []);
  const [done, setDone] = useState(false);  // the answer above is read once, so it cannot know about this
  useEffect(() => {
    const finished = () => setDone(true);
    window.addEventListener(SETUP_COMPLETED, finished);
    return () => window.removeEventListener(SETUP_COMPLETED, finished);
  }, []);
  if (loading) return null;
  // If the setup state cannot be read, do not block the app.
  const needsSetup = data && data.system_logs_enabled && !data.completed && !done;
  if (needsSetup && location.pathname !== "/setup") return <Navigate to="/setup" replace />;
  return children;
}
