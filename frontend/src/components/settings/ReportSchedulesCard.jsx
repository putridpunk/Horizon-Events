import { useState } from "react";
import usePolling from "../../services/usePolling.js";
import {
  createReportSchedule, deleteReportSchedule, listNotificationChannels, listReportSchedules,
  reportScheduleDownloadUrl, runReportSchedule, updateReportSchedule,
} from "../../services/api.js";
import { EmptyState, ErrorBanner } from "../common.jsx";
import Time from "../ui/Time.jsx";

const BLANK = { name: "", frequency: "weekly", format: "html", email_channel_id: "" };

/** Reports that make themselves: saved to the reports folder every morning or Monday, and optionally emailed. */
export default function ReportSchedulesCard() {
  const { data, error, reload } = usePolling(listReportSchedules, [], 0);
  const { data: channels } = usePolling(listNotificationChannels, [], 15000);
  const [form, setForm] = useState(null);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);

  const mailChannels = (channels?.items ?? []).filter((c) => c.kind === "email");
  const set = (key) => (e) => setForm((f) => ({ ...f, [key]: e.target.value }));

  async function run(action, done) {
    setBusy(true);
    setMessage(null);
    try {
      await action();
      await reload();
      done?.();
    } catch (e) {
      setMessage(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  const save = (e) => {
    e.preventDefault();
    return run(() => createReportSchedule({
      name: form.name, frequency: form.frequency, format: form.format,
      email_channel_id: form.email_channel_id ? Number(form.email_channel_id) : null,
    }), () => setForm(null));
  };

  const items = data?.items ?? [];
  return (
    <section className="card">
      <h2>Scheduled reports</h2>
      <p className="muted">
        A report is made at 07:00 UTC every day, or every Monday, and saved in the reports folder. It covers the previous day or
        week. Pick an email channel to have it sent as well.
      </p>
      <ErrorBanner error={error} />
      {message && <div className="error" role="alert">{message}</div>}
      {data && items.length === 0 && !form && <EmptyState>No scheduled reports.</EmptyState>}
      {items.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Runs</th><th>Format</th><th>Next run</th><th>Last run</th><th /></tr></thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id}>
                  <td>{s.name}{!s.enabled && <span className="muted"> (off)</span>}</td>
                  <td>{s.frequency}</td>
                  <td>{s.format}</td>
                  <td><Time value={s.next_run} upcoming /></td>
                  <td>
                    {s.last_run ? <Time value={s.last_run} /> : "-"}
                    {s.last_error && <div className="sla-late">{s.last_error}</div>}
                  </td>
                  <td className="actions">
                    <button disabled={busy} onClick={() => run(() => runReportSchedule(s.id))}
                      aria-label={`Make ${s.name} now`}>Run now</button>
                    {s.last_file && <a className="button" href={reportScheduleDownloadUrl(s.id)} download>Download latest</a>}
                    <button disabled={busy} onClick={() => run(() => updateReportSchedule(s.id, { enabled: !s.enabled }))}
                      aria-label={`${s.enabled ? "Turn off" : "Turn on"} ${s.name}`}>{s.enabled ? "Turn off" : "Turn on"}</button>
                    <button disabled={busy} onClick={() => run(() => deleteReportSchedule(s.id))}
                      aria-label={`Remove ${s.name}`}>Remove</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {form ? (
        <form className="settings-form" onSubmit={save} aria-label="Add a scheduled report">
          <label>Name<input required value={form.name} onChange={set("name")} maxLength={100} /></label>
          <label>How often
            <select value={form.frequency} onChange={set("frequency")}>
              <option value="daily">Every day</option><option value="weekly">Every Monday</option>
            </select>
          </label>
          <label>Format
            <select value={form.format} onChange={set("format")}>
              <option value="html">HTML</option><option value="csv">CSV</option><option value="json">JSON</option>
            </select>
          </label>
          <label>Also email it
            <select value={form.email_channel_id} onChange={set("email_channel_id")}>
              <option value="">No</option>
              {mailChannels.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </label>
          <div className="actions">
            <button type="submit" className="primary" disabled={busy}>Add schedule</button>
            <button type="button" disabled={busy} onClick={() => setForm(null)}>Cancel</button>
          </div>
        </form>
      ) : (
        <p><button onClick={() => setForm({ ...BLANK })}>Add a scheduled report…</button></p>
      )}
    </section>
  );
}
