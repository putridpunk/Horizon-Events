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
import SetupGate from "./components/SetupGate.jsx";

export default function App() {
  return (
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
        <Route path="/setup" element={<Setup />} />
        <Route path="*" element={<Overview />} />
      </Routes>
      </SetupGate>
    </Layout>
  );
}
