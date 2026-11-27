import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import AlertDrawer from "../components/AlertDrawer.jsx";
import NotificationsCard from "../components/settings/NotificationsCard.jsx";
import ReportSchedulesCard from "../components/settings/ReportSchedulesCard.jsx";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import Alerts from "./Alerts.jsx";

vi.mock("../services/api.js");

const ALERT = {
  id: 5, alert_id: "ALT-000005", rule_id: "HZ-001", rule_name: "Repeated login failures", severity: "high", status: "OPEN",
  description: "d", source_ip: "8.8.4.4", username: "admin", occurrences: 3, window_minutes: 5, techniques: [],
  created_at: "2026-11-24T09:00:00", last_seen: "2026-11-24T09:00:00", intel: null, events: [], history: [],
  assignee: null, tags: [], age_minutes: 90, sla_minutes: 240, sla_breached: false,
};

describe("Owner and tags in the alert drawer", () => {
  it("saves a trimmed owner and a clean list of tags", async () => {
    mockApiDefaults();
    vi.mocked(api.getAlert).mockResolvedValue(ALERT);
    vi.mocked(api.triageAlert).mockResolvedValue({});
    render(<MemoryRouter><AlertDrawer alertId={5} onClose={() => {}} onChanged={() => {}} /></MemoryRouter>);
    await userEvent.type(await screen.findByLabelText("Owner"), "  Ana ");
    await userEvent.type(screen.getByLabelText("Tags"), "phishing, , vip ");
    await userEvent.click(screen.getByRole("button", { name: "Save owner and tags" }));
    await waitFor(() => expect(api.triageAlert).toHaveBeenCalledWith(5, { assignee: "Ana", tags: ["phishing", "vip"] }));
  });

  it("clears the owner when the field is emptied, and shows the server's error", async () => {
    mockApiDefaults();
    vi.mocked(api.getAlert).mockResolvedValue({ ...ALERT, assignee: "Ana", tags: ["vip"] });
    vi.mocked(api.triageAlert).mockRejectedValue(new Error("An alert can have at most 10 tags."));
    render(<MemoryRouter><AlertDrawer alertId={5} onClose={() => {}} /></MemoryRouter>);
    await userEvent.clear(await screen.findByLabelText("Owner"));
    await userEvent.click(screen.getByRole("button", { name: "Save owner and tags" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("at most 10 tags");
    expect(api.triageAlert).toHaveBeenCalledWith(5, { assignee: null, tags: ["vip"] });
  });

  it("says when an alert is late", async () => {
    mockApiDefaults();
    vi.mocked(api.getAlert).mockResolvedValue({ ...ALERT, age_minutes: 300, sla_breached: true });
    render(<MemoryRouter><AlertDrawer alertId={5} onClose={() => {}} /></MemoryRouter>);
    expect(await screen.findByText(/This alert is late/)).toBeInTheDocument();
  });
});

describe("Alerts list", () => {
  it("shows owner, tags and late marker, and filters by owner", async () => {
    mockApiDefaults();
    vi.mocked(api.listAlertTags).mockResolvedValue({ tags: ["vip"], assignees: ["Ana"] });
    vi.mocked(api.listAlerts).mockResolvedValue({
      items: [{ ...ALERT, assignee: "Ana", tags: ["vip"], sla_breached: true }], total: 1 });
    render(<MemoryRouter><Alerts /></MemoryRouter>);
    const row = (await screen.findByText("ALT-000005")).closest("tr");
    expect(within(row).getByText("Ana")).toBeInTheDocument();
    expect(within(row).getByText("vip")).toBeInTheDocument();
    expect(within(row).getByText("late")).toBeInTheDocument();
    await userEvent.selectOptions(await screen.findByLabelText("Owner"), "unassigned");
    await waitFor(() => expect(vi.mocked(api.listAlerts).mock.calls.at(-1)[0]).toMatchObject({ assignee: "unassigned" }));
  });
});

const CHANNEL = { id: 1, name: "Ops chat", kind: "slack", config: { url_host: "hooks.slack.com", has_url: true },
  min_severity: "high", enabled: true, created_at: "2026-11-24T09:00:00", last_sent: null, last_error: null, sent_count: 0 };

describe("Notifications settings", () => {
  it("lists channels without showing the secret address, only its host", async () => {
    mockApiDefaults();
    vi.mocked(api.listNotificationChannels).mockResolvedValue({ items: [CHANNEL], kinds: [] });
    render(<NotificationsCard />);
    expect(await screen.findByText("Ops chat")).toBeInTheDocument();
    expect(screen.getByText("hooks.slack.com")).toBeInTheDocument();
  });

  it("adds a Slack channel with the chosen severity", async () => {
    mockApiDefaults();
    vi.mocked(api.createNotificationChannel).mockResolvedValue(CHANNEL);
    render(<NotificationsCard />);
    await userEvent.click(await screen.findByRole("button", { name: /Add a channel/ }));
    await userEvent.type(screen.getByLabelText("Name"), "Ops chat");
    await userEvent.type(screen.getByLabelText("Address"), "https://hooks.slack.com/services/T/B/X");
    await userEvent.selectOptions(screen.getByLabelText("Send alerts from severity"), "critical");
    await userEvent.click(screen.getByRole("button", { name: "Add channel" }));
    await waitFor(() => expect(api.createNotificationChannel).toHaveBeenCalledWith({
      name: "Ops chat", kind: "slack", min_severity: "critical", config: { url: "https://hooks.slack.com/services/T/B/X" } }));
  });

  it("asks for mail settings when the type is email", async () => {
    mockApiDefaults();
    vi.mocked(api.createNotificationChannel).mockResolvedValue(CHANNEL);
    render(<NotificationsCard />);
    await userEvent.click(await screen.findByRole("button", { name: /Add a channel/ }));
    await userEvent.selectOptions(screen.getByLabelText("Type"), "email");
    await userEvent.type(screen.getByLabelText("Name"), "Mail");
    await userEvent.type(screen.getByLabelText("Mail server"), "smtp.example.com");
    await userEvent.type(screen.getByLabelText("Send from"), "h@example.com");
    await userEvent.type(screen.getByLabelText(/Send to/), "a@example.com");
    await userEvent.click(screen.getByRole("button", { name: "Add channel" }));
    await waitFor(() => expect(api.createNotificationChannel).toHaveBeenCalled());
    const body = vi.mocked(api.createNotificationChannel).mock.calls[0][0];
    expect(body.kind).toBe("email");
    expect(body.config).toMatchObject({ host: "smtp.example.com", from_addr: "h@example.com", to_addrs: "a@example.com", security: "starttls" });
  });

  it("reports whether the test message arrived", async () => {
    mockApiDefaults();
    vi.mocked(api.listNotificationChannels).mockResolvedValue({ items: [CHANNEL], kinds: [] });
    vi.mocked(api.testNotificationChannel).mockResolvedValueOnce({ ok: true })
      .mockResolvedValueOnce({ ok: false, error: "the server answered with status 404" });
    render(<NotificationsCard />);
    await userEvent.click(await screen.findByRole("button", { name: "Send a test to Ops chat" }));
    expect(await screen.findByText("Test message sent to Ops chat.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Send a test to Ops chat" }));
    expect(await screen.findByText(/failed: the server answered with status 404/)).toBeInTheDocument();
  });

  it("shows why a channel last failed", async () => {
    mockApiDefaults();
    vi.mocked(api.listNotificationChannels).mockResolvedValue({
      items: [{ ...CHANNEL, last_error: "the server answered with status 500" }], kinds: [] });
    render(<NotificationsCard />);
    expect(await screen.findByText("the server answered with status 500")).toBeInTheDocument();
  });
});

describe("Scheduled reports settings", () => {
  it("creates a weekly report and offers only email channels", async () => {
    mockApiDefaults();
    vi.mocked(api.listNotificationChannels).mockResolvedValue({
      items: [CHANNEL, { ...CHANNEL, id: 2, name: "Boss mail", kind: "email", config: {} }], kinds: [] });
    vi.mocked(api.createReportSchedule).mockResolvedValue({});
    render(<ReportSchedulesCard />);
    await userEvent.click(await screen.findByRole("button", { name: /Add a scheduled report/ }));
    await userEvent.type(screen.getByLabelText("Name"), "Monday summary");
    const mail = await screen.findByRole("option", { name: "Boss mail" });
    expect(screen.queryByRole("option", { name: "Ops chat" })).not.toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Also email it"), mail);
    await userEvent.click(screen.getByRole("button", { name: "Add schedule" }));
    await waitFor(() => expect(api.createReportSchedule).toHaveBeenCalledWith({
      name: "Monday summary", frequency: "weekly", format: "html", email_channel_id: 2 }));
  });

  it("runs a schedule now and links to the latest file", async () => {
    mockApiDefaults();
    const s = { id: 3, name: "Daily", frequency: "daily", format: "csv", email_channel_id: null, enabled: true,
      created_at: "2026-11-24T09:00:00", next_run: "2026-11-25T07:00:00", last_run: "2026-11-24T07:00:00",
      last_file: "report-3-x.csv", last_error: null };
    vi.mocked(api.listReportSchedules).mockResolvedValue({ items: [s], frequencies: [], formats: [] });
    vi.mocked(api.runReportSchedule).mockResolvedValue(s);
    render(<ReportSchedulesCard />);
    await userEvent.click(await screen.findByRole("button", { name: "Make Daily now" }));
    await waitFor(() => expect(api.runReportSchedule).toHaveBeenCalledWith(3));
    expect(screen.getByRole("link", { name: "Download latest" })).toHaveAttribute("href", "/api/report-schedules/3/latest");
  });
});
