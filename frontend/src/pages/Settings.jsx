import { useAuth } from "../auth/AuthGate.jsx";
import { PageHeader } from "../components/common.jsx";
import LanguageCard from "../components/settings/LanguageCard.jsx";
import DesktopCard from "../components/settings/DesktopCard.jsx";
import DownloadsCard from "../components/settings/DownloadsCard.jsx";
import DataCard from "../components/settings/DataCard.jsx";
import SuppressionsCard from "../components/settings/SuppressionsCard.jsx";
import AccountCard from "../components/settings/AccountCard.jsx";
import UsersCard from "../components/settings/UsersCard.jsx";
import UpdateCard from "../components/settings/UpdateCard.jsx";
import GeoIpCard from "../components/settings/GeoIpCard.jsx";
import NotificationsCard from "../components/settings/NotificationsCard.jsx";
import ReportSchedulesCard from "../components/settings/ReportSchedulesCard.jsx";

export default function Settings() {
  const { enabled, user } = useAuth();
  const admin = !enabled || user?.role === "admin";
  return (
    <>
      <PageHeader title="Settings" subtitle="How Horizon Events behaves on this computer" />
      <AccountCard />
      <UsersCard />
      <LanguageCard />
      <DesktopCard />
      <DownloadsCard />
      <DataCard />
      {admin && <GeoIpCard />}
      {admin && <NotificationsCard />}
      {admin && <ReportSchedulesCard />}
      <SuppressionsCard />
      <UpdateCard />
    </>
  );
}
