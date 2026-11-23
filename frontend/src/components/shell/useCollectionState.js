import usePolling from "../../services/usePolling.js";
import { getCollectors, getWatcherStatus } from "../../services/api.js";

/** Whether anything is currently feeding events in: a system log source or the watch folder. */
export default function useCollectionState() {
  const { data } = usePolling(async () => {
    const [collectors, watcher] = await Promise.allSettled([getCollectors(), getWatcherStatus()]);
    const sources = collectors.status === "fulfilled" ? collectors.value.items ?? [] : [];
    const folder = watcher.status === "fulfilled" ? watcher.value : null;
    const collecting = sources.filter((s) => s.state === "collecting").length;
    const watching = Boolean(folder?.enabled && folder?.running && !folder?.paused);
    return { active: collecting > 0 || watching, collecting, watching };
  }, [], 5000);
  return data ?? { active: false, collecting: 0, watching: false };
}
