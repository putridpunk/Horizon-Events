export const SEVERITIES = ["critical", "high", "medium", "low"];
export const SOURCES = ["linux_auth", "linux_syslog", "windows", "application", "json"];
export const EVENT_TYPES = [
  "authentication_success",
  "authentication_failure",
  "unknown_user",
  "account_lockout",
  "privilege_escalation",
  "service_failure",
  "service_start",
  "generic",
];
export const STATUSES = ["OPEN", "INVESTIGATING", "RESOLVED"];
export const COLORS = {
  critical: "#ff4d5e",
  high: "#ff9248",
  medium: "#f5c542",
  low: "#4aa3ff",
  accent: "#29d3ff",
  grid: "rgba(138, 155, 184, 0.14)",
  text: "#8a9bb8",
};

export const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString() : "-");
