import { parseTimestamp } from "../lib/time.js";

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
  "log_cleared",
  "service_installed",
  "scheduled_task_created",
  "remote_login",
  "explicit_credentials",
  "ntlm_logon",
  "powershell_script",
  "usb_device",
  "generic",
];
export const STATUSES = ["OPEN", "INVESTIGATING", "RESOLVED"];

export const fmtTime = (iso) => parseTimestamp(iso)?.toLocaleString() ?? "-";
