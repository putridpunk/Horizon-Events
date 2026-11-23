import { vi } from "vitest";
import * as api from "../services/api.js";
import { emptyOverview } from "./fixtures.js";

/** Give every mocked API function a harmless empty-database default. Call after `vi.mock("…/api.js")`. */
export function mockApiDefaults() {
  const m = vi.mocked(api);
  m.getOverview.mockResolvedValue(emptyOverview);
  m.getTimeseries.mockResolvedValue([]);
  m.getEventTypes.mockResolvedValue([]);
  m.getSourceIps.mockResolvedValue([]);
  m.getSeverity.mockResolvedValue([]);
  m.getRuleStats.mockResolvedValue([]);
  m.getMitreStats.mockResolvedValue({ tactics: [], techniques: [] });
  m.listEvents.mockResolvedValue({ items: [], total: 0 });
  m.listAlerts.mockResolvedValue({ items: [], total: 0 });
  m.listIncidents.mockResolvedValue({ items: [], total: 0 });
  m.getModelStatus.mockResolvedValue({ trained: false, trained_at: null, windows: 0, source: null, features: ["events", "failures"] });
  m.getIntelStatus.mockResolvedValue({ feeds: [], min_refresh_minutes: 60 });
  m.getWatcherStatus.mockResolvedValue({ enabled: false });
  m.reportUrl.mockImplementation((start, end, format) => `/api/reports?format=${format}`);
  return m;
}
