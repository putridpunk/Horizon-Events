// Shared test data shaped like the API's responses.
export const technique = (over = {}) => ({
  id: "T1110", name: "Brute Force", tactics: ["Credential Access"],
  url: "https://attack.mitre.org/techniques/T1110/", confidence: "high", ...over,
});

export const alert = (over = {}) => ({
  id: 1, alert_id: "ALT-000001", rule_id: "HZ-001", rule_name: "Repeated login failures", severity: "critical",
  status: "OPEN", description: "An unusually high number of failed authentication attempts was detected.",
  source_ip: "192.168.1.15", username: "admin", occurrences: 12, window_minutes: 5,
  created_at: "2026-11-23T14:21:20", last_seen: "2026-11-23T14:21:20",
  techniques: [technique()], intel: { listed: false, feeds: [] }, ...over,
});

export const alertDetail = (over = {}) => ({
  ...alert(),
  events: [{ id: 1, timestamp: "2026-11-23T14:20:31", event_type: "authentication_failure", username: "admin", source_ip: "192.168.1.15" }],
  history: [{ from_status: null, to_status: "OPEN", note: "Alert created by detection engine", at: "2026-11-23T14:21:20" }],
  ...over,
});

export const incident = (over = {}) => ({
  id: 1, incident_id: "INC-000001", title: "Repeated login failures from 192.168.1.15", severity: "critical",
  status: "OPEN", alert_count: 2, created_at: "2026-11-23T14:21:20", last_activity: "2026-11-23T14:45:10", ...over,
});

export const incidentDetail = (over = {}) => ({
  ...incident(),
  alerts: [alert(), alert({ id: 5, alert_id: "ALT-000005", rule_id: "HZ-006", rule_name: "Account lockouts", severity: "high",
    source_ip: null, intel: { listed: true, feeds: [{ id: "demo", name: "Synthetic demo feed" }] } })],
  history: [{ action: "created", detail: "Opened automatically from ALT-000001", from_status: null, to_status: null, at: "2026-11-23T14:21:20" }],
  ips: ["192.168.1.15"], accounts: ["admin"], techniques: [technique()], first_activity: "2026-11-23T14:20:31", ...over,
});

export const event = (over = {}) => ({
  id: 1, timestamp: "2026-11-23T14:20:31", source: "linux_auth", event_type: "authentication_failure", severity: "medium",
  username: "admin", source_ip: "192.168.1.15", host: "web01", service: null, message: "Failed password for admin",
  raw: "Nov 23 14:20:31 web01 sshd[1]: Failed password for admin", metadata: {}, ...over,
});

export const collector = (over = {}) => ({
  id: "windows-system", name: "Windows System log", description: "Services that crash or stop unexpectedly.",
  platform: "windows", enabled: false, access: "ready", state: "off", events_read: 0, last_activity: null,
  last_error: null, ...over,
});

export const emptyOverview = { total_events: 0, total_alerts: 0, open_alerts: 0, critical_alerts: 0, high_alerts: 0, sources: 0 };
