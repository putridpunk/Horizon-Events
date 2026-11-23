import { Navigate, useLocation } from "react-router-dom";
import usePolling from "../services/usePolling.js";
import { getSetup } from "../services/api.js";

/** Sends the user to the first-run setup until it has been completed (only when system logs are available). */
export default function SetupGate({ children }) {
  const location = useLocation();
  const { data, loading } = usePolling(getSetup, []);
  if (loading) return null;
  // If the setup state cannot be read, do not block the app.
  const needsSetup = data && data.system_logs_enabled && !data.completed;
  if (needsSetup && location.pathname !== "/setup") return <Navigate to="/setup" replace />;
  return children;
}
