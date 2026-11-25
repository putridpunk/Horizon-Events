const BASE = "/api";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, options);
  if (!res.ok) {
    let detail = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d) => d.msg).join("; ");
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail);
  }
  return res.json();
}

const qs = (params = {}) => {
  const p = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") p.set(k, v);
  });
  const s = p.toString();
  return s ? `?${s}` : "";
};

const json = (method, body) => ({
  method,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const getOverview = () => request("/statistics/overview");
export const getTimeseries = (params) => request(`/statistics/timeseries${qs(params)}`);
export const getEventTypes = () => request("/statistics/event-types");
export const getSourceIps = () => request("/statistics/source-ips");
export const getSeverity = () => request("/statistics/severity");
export const getRuleStats = () => request("/statistics/rules");

export const listEvents = (params) => request(`/events${qs(params)}`);
export const getEvent = (id) => request(`/events/${id}`);

export const listAlerts = (params) => request(`/alerts${qs(params)}`);
export const getAlert = (id) => request(`/alerts/${id}`);
export const updateAlert = (id, body) => request(`/alerts/${id}`, json("PATCH", body));

export const listRules = () => request("/rules");
export const updateRule = (id, patch) => request(`/rules/${id}`, json("PATCH", patch));

export function importLogs(file, sourceType) {
  const form = new FormData();
  form.append("file", file);
  form.append("source_type", sourceType);
  return request("/imports", { method: "POST", body: form });
}

export const getReport = (start, end) => request(`/reports${qs({ start, end, format: "json" })}`);
export const reportUrl = (start, end, format) => `${BASE}/reports${qs({ start, end, format })}`;

export const getModelStatus = () => request("/ml/status");
export const trainModel = (source) => request("/ml/train", json("POST", { source }));

export const getMitreStats = () => request("/statistics/mitre");

export const getWatcherStatus = () => request("/watcher/status");
export const pauseWatcher = () => request("/watcher/pause", { method: "POST" });
export const resumeWatcher = () => request("/watcher/resume", { method: "POST" });

export const getIntelStatus = () => request("/intel/status");
export const refreshIntel = () => request("/intel/refresh", json("POST", {}));

export const listIncidents = (params) => request(`/incidents${qs(params)}`);
export const getIncident = (id) => request(`/incidents/${id}`);
export const updateIncident = (id, body) => request(`/incidents/${id}`, json("PATCH", body));
export const addIncidentNote = (id, text) => request(`/incidents/${id}/notes`, json("POST", { text }));
export const removeIncidentAlert = (id, alertId) => request(`/incidents/${id}/alerts/${alertId}`, { method: "DELETE" });
export const mergeIncident = (id, into) => request(`/incidents/${id}/merge`, json("POST", { into }));

export const getCollectors = () => request("/collectors");
export const updateCollector = (id, body) => request(`/collectors/${id}`, json("PATCH", body));
export const checkCollector = (id) => request(`/collectors/${id}/check`, { method: "POST" });
export const enableSecurityAccess = () => request("/collectors/security/enable-access", { method: "POST" });
export const getSetup = () => request("/setup");
export const completeSetup = () => request("/setup/complete", { method: "POST" });

export const getScanStatus = () => request("/scans/status");
export const listScans = () => request("/scans");
export const getScan = (id) => request(`/scans/${id}`);
export const startScan = (paths) => request("/scans", json("POST", { paths }));

export const getMitigationSettings = () => request("/mitigation/settings");
export const updateMitigationSettings = (body) => request("/mitigation/settings", json("PUT", body));
export const getAlertMitigation = (alertId) => request(`/mitigation/alerts/${alertId}`);
export const getMitigationHistory = () => request("/mitigation/history");
export const approveMitigation = (id) => request(`/mitigation/${id}/approve`, { method: "POST" });
export const dismissMitigation = (id) => request(`/mitigation/${id}/dismiss`, { method: "POST" });
export const undoMitigation = (id) => request(`/mitigation/${id}/undo`, { method: "POST" });

export const listSuppressions = () => request("/suppressions");
export const createSuppression = (body) => request("/suppressions", json("POST", body));
export const deleteSuppression = (id) => request(`/suppressions/${id}`, { method: "DELETE" });
export const suppressAlert = (alertId) => request(`/alerts/${alertId}/suppress`, { method: "POST" });

export const getDataStatus = () => request("/data/status");
export const setRetention = (days) => request("/data/retention", json("PUT", { days }));
export const purgeOldEvents = () => request("/data/purge", { method: "POST" });
export const backupData = (path) => request("/data/backup", json("POST", { path }));
export const restoreData = (path) => request("/data/restore", json("POST", { path }));
export const cancelRestore = () => request("/data/restore", { method: "DELETE" });

export const getDownloadsScan = () => request("/scans/downloads");
export const updateDownloadsScan = (body) => request("/scans/downloads", json("PUT", body));

export const getDesktopSettings = () => request("/desktop/settings");
export const updateDesktopSettings = (body) => request("/desktop/settings", json("PUT", body));
