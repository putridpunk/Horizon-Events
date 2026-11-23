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
