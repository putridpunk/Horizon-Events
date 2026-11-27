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
  m.listSuppressions.mockImplementation(later({ items: [] }));
  m.getDataStatus.mockImplementation(later({ backups_available: false, retention_days: 0, events: 0, oldest_event: null, database_bytes: null, restore_pending: false }));
  m.getDownloadsScan.mockImplementation(later({ available: false, enabled: false, folder: "", default_folder: "C:/Users/me/Downloads", effective_folder: "C:/Users/me/Downloads", watching: false, queued: 0, scanned: 0 }));
  m.getDesktopSettings.mockImplementation(later({ enabled: false }));
  m.listSavedSearches.mockImplementation(later({ items: [], fields: [] }));
  m.exportEventsUrl.mockImplementation((p, format) => `/api/events/export?format=${format}`);
  m.getSyslogStatus.mockImplementation(later({ enabled: false }));
  m.listRules.mockImplementation(later([]));
  m.getGeoIp.mockImplementation(later({ configured: false, path: null, database: null, error: null, from_environment: false }));
  m.getAuthStatus.mockImplementation(later({ enabled: false, setup_required: false, user: null }));
  m.getUpdateStatus.mockImplementation(later({ current: "1.5.0", auto_check: false, checked_at: null, latest: null, update_available: false, url: null, notes: null, error: null }));
  m.listUsers.mockImplementation(later({ items: [], roles: ["viewer", "analyst", "admin"] }));
  m.getAudit.mockImplementation(later({ items: [] }));
  m.listAlertTags.mockImplementation(later({ tags: [], assignees: [] }));
  m.listNotificationChannels.mockImplementation(later({ items: [], kinds: ["webhook", "slack", "discord", "email"] }));
  m.listReportSchedules.mockImplementation(later({ items: [], frequencies: ["daily", "weekly"], formats: ["json", "csv", "html"] }));
  m.reportScheduleDownloadUrl.mockImplementation((id) => `/api/report-schedules/${id}/latest`);
  m.reportUrl.mockImplementation((start, end, format) => `/api/reports?format=${format}`);
  return m;
}
