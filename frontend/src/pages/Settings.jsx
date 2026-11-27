import { PageHeader } from "../components/common.jsx";
import LanguageCard from "../components/settings/LanguageCard.jsx";
import DesktopCard from "../components/settings/DesktopCard.jsx";
import DownloadsCard from "../components/settings/DownloadsCard.jsx";
import DataCard from "../components/settings/DataCard.jsx";
import SuppressionsCard from "../components/settings/SuppressionsCard.jsx";
import GeoIpCard from "../components/settings/GeoIpCard.jsx";
import NotificationsCard from "../components/settings/NotificationsCard.jsx";
import ReportSchedulesCard from "../components/settings/ReportSchedulesCard.jsx";

export default function Settings() {
  return (
    <>
      <PageHeader title="Settings" subtitle="How Horizon Events behaves on this computer" />
      <LanguageCard />
      <DesktopCard />
      <DownloadsCard />
      <DataCard />
      <GeoIpCard />
      <NotificationsCard />
      <ReportSchedulesCard />
      <SuppressionsCard />
    </>
  );
}
