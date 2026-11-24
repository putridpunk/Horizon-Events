import { vi } from "vitest";
import * as api from "../services/api.js";
import { emptyOverview } from "./fixtures.js";

/** Resolve after a short delay, like a real network, so tests cannot rely on data arriving instantly. */
const later = (value, ms = 30) => () => new Promise((resolve) => setTimeout(() => resolve(value), ms));

/** Give every mocked API function a harmless empty-database default. Call after `vi.mock("…/api.js")`. */
export function mockApiDefaults() {
  const m = vi.mocked(api);
  m.getOverview.mockImplementation(later(emptyOverview));
  m.getTimeseries.mockImplementation(later([]));
  m.getEventTypes.mockImplementation(later([]));
  m.getSourceIps.mockImplementation(later([]));
  m.getSeverity.mockImplementation(later([]));
  m.getRuleStats.mockImplementation(later([]));
  m.getMitreStats.mockImplementation(later({ tactics: [], techniques: [] }));
  m.listEvents.mockImplementation(later({ items: [], total: 0 }));
  m.listAlerts.mockImplementation(later({ items: [], total: 0 }));
  m.listIncidents.mockImplementation(later({ items: [], total: 0 }));
  m.getModelStatus.mockImplementation(later({ trained: false, trained_at: null, windows: 0, source: null, features: ["events", "failures"] }));
  m.getIntelStatus.mockImplementation(later({ feeds: [], min_refresh_minutes: 60 }));
  m.getWatcherStatus.mockImplementation(later({ enabled: false }));
  m.getSetup.mockImplementation(later({ completed: true, system_logs_enabled: false, platform: "windows" }));
  m.getCollectors.mockImplementation(later({ enabled: false, platform: "windows", items: [] }));
  m.getScanStatus.mockImplementation(later({ enabled: false, engine: "Microsoft Defender", available: false, message: "File scanning is only available in the desktop app." }));
  m.listScans.mockImplementation(later({ items: [] }));
  m.getAlertMitigation.mockImplementation(later({ enabled: false, advice: ["Review the related events."], actions: [], skipped: [] }));
  m.getMitigationSettings.mockImplementation(later({ enabled: false, block_ip: "ask", quarantine_file: "ask", block_private: false, block_days: 7, allowlist: [] }));
  m.getMitigationHistory.mockImplementation(later({ items: [] }));
  m.reportUrl.mockImplementation((start, end, format) => `/api/reports?format=${format}`);
  return m;
}
