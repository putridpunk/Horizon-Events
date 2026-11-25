import { PageHeader } from "../components/common.jsx";
import DownloadsCard from "../components/settings/DownloadsCard.jsx";
import DataCard from "../components/settings/DataCard.jsx";
import SuppressionsCard from "../components/settings/SuppressionsCard.jsx";

export default function Settings() {
  return (
    <>
      <PageHeader title="Settings" subtitle="How Horizon Events behaves on this computer" />
      <DownloadsCard />
      <DataCard />
      <SuppressionsCard />
    </>
  );
}
