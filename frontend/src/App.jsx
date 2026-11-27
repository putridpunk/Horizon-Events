import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout.jsx";
import Overview from "./pages/Overview.jsx";
import Events from "./pages/Events.jsx";
import Alerts from "./pages/Alerts.jsx";
import Incidents from "./pages/Incidents.jsx";
import Analytics from "./pages/Analytics.jsx";
import Reports from "./pages/Reports.jsx";
import Setup from "./pages/Setup.jsx";
import Sources from "./pages/Sources.jsx";
import Scan from "./pages/Scan.jsx";
import Mitigation from "./pages/Mitigation.jsx";
import Settings from "./pages/Settings.jsx";
import Rules from "./pages/Rules.jsx";
import SetupGate from "./components/SetupGate.jsx";
import AuthGate from "./auth/AuthGate.jsx";

export default function App() {
  return (
    <AuthGate>
    <Layout>
      <SetupGate>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/events" element={<Events />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/analytics" element={<Analytics />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/sources" element={<Sources />} />
        <Route path="/scan" element={<Scan />} />
        <Route path="/mitigation" element={<Mitigation />} />
        <Route path="/rules" element={<Rules />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/setup" element={<Setup />} />
        <Route path="*" element={<Overview />} />
      </Routes>
      </SetupGate>
    </Layout>
    </AuthGate>
  );
}
