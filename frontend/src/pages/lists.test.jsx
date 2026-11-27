import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { alert, alertDetail, event, incident, incidentDetail } from "../test/fixtures.js";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import Alerts from "./Alerts.jsx";
import Events from "./Events.jsx";
import Incidents from "./Incidents.jsx";

vi.mock("../services/api.js");

const lastCallArgs = (fn) => fn.mock.calls.at(-1)[0];

describe("Incidents page", () => {
  it("lists incidents with severity, status and alert count", async () => {
    mockApiDefaults();
    vi.mocked(api.listIncidents).mockResolvedValue({ items: [
      incident(), incident({ id: 2, incident_id: "INC-000002", title: "Unknown users from 203.0.113.7", severity: "high", alert_count: 1 }),
    ], total: 2 });
    render(<Incidents />);
    expect(await screen.findByText("INC-000002")).toBeInTheDocument();
    expect(screen.getByText("Unknown users from 203.0.113.7")).toBeInTheDocument();
    expect(screen.getByText("Page 1 of 1 · 2 total")).toBeInTheDocument();
  });

  it("shows an empty state that explains where incidents come from", async () => {
    mockApiDefaults();
    render(<Incidents />);
    expect(await screen.findByText(/created automatically as alerts are raised/)).toBeInTheDocument();
  });

  it("passes the chosen filters to the API and returns to the first page", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    render(<Incidents />);
    await screen.findByText(/created automatically/);
    await user.selectOptions(screen.getAllByRole("combobox")[0], "high");
    await user.selectOptions(screen.getAllByRole("combobox")[1], "RESOLVED");
    await waitFor(() => expect(lastCallArgs(api.listIncidents)).toMatchObject({ severity: "high", status: "RESOLVED", offset: 0 }));
  });

  it("opens the incident drawer when a row is clicked", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    vi.mocked(api.listIncidents).mockResolvedValue({ items: [incident()], total: 1 });
    vi.mocked(api.getIncident).mockResolvedValue(incidentDetail());
    render(<Incidents />);
    await user.click(await screen.findByText("Repeated login failures from 192.168.1.15"));
    expect(await screen.findByText("Alerts (2)")).toBeInTheDocument();
    expect(api.getIncident).toHaveBeenCalledWith(1);
  });

  it("shows a banner instead of crashing when the API is down", async () => {
    mockApiDefaults();
    vi.mocked(api.listIncidents).mockRejectedValue(new Error("Request failed (500)"));
    render(<Incidents />);
    expect(await screen.findByText(/Could not load data: Request failed \(500\)/)).toBeInTheDocument();
  });
});

describe("Alerts page", () => {
  it("shows alerts with technique and threat-intel badges", async () => {
    mockApiDefaults();
    vi.mocked(api.listAlerts).mockResolvedValue({ items: [
      alert(), alert({ id: 2, alert_id: "ALT-000002", rule_id: "HZ-007", rule_name: "Anomalous IP activity", severity: "high",
        source_ip: "198.51.100.77", intel: { listed: true, feeds: [{ id: "demo", name: "Synthetic demo feed" }] }, techniques: [] }),
    ], total: 2 });
    render(<Alerts />);
    expect(await screen.findByText("ALT-000002")).toBeInTheDocument();
    expect(screen.getAllByText("Known malicious")).toHaveLength(1);
    expect(screen.getByRole("link", { name: "T1110" })).toBeInTheDocument();
  });

  it("shows an empty state", async () => {
    mockApiDefaults();
    render(<Alerts />);
    expect(await screen.findByText("No alerts match the current filters.")).toBeInTheDocument();
  });

  it("filters by severity and status", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    render(<Alerts />);
    await screen.findByText(/No alerts match/);
    await user.selectOptions(screen.getAllByRole("combobox")[0], "critical");
    await user.selectOptions(screen.getAllByRole("combobox")[1], "OPEN");
    await waitFor(() => expect(lastCallArgs(api.listAlerts)).toMatchObject({ severity: "critical", status: "OPEN" }));
  });

  it("opens the alert drawer from a row", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    vi.mocked(api.listAlerts).mockResolvedValue({ items: [alert()], total: 1 });
    vi.mocked(api.getAlert).mockResolvedValue(alertDetail());
    render(<Alerts />);
    await user.click(await screen.findByText("ALT-000001"));
    expect(await screen.findByText("Related events (1)")).toBeInTheDocument();
  });

  it("shows a banner when the API fails", async () => {
    mockApiDefaults();
    vi.mocked(api.listAlerts).mockRejectedValue(new Error("down"));
    render(<Alerts />);
    expect(await screen.findByText(/Could not load data: down/)).toBeInTheDocument();
  });
});

describe("Events page", () => {
  it("shows an empty state", async () => {
    mockApiDefaults();
    render(<Events />);
    expect(await screen.findByText(/No events match/)).toBeInTheDocument();
  });

  it("lists events and opens the raw log in a detail dialog", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    vi.mocked(api.listEvents).mockResolvedValue({ items: [event()], total: 1 });
    vi.mocked(api.getEvent).mockResolvedValue(event());
    render(<Events />);
    await user.click(await screen.findByText("Failed password for admin"));
    expect(await screen.findByText("Event #1")).toBeInTheDocument();
    expect(screen.getByText("Raw log")).toBeInTheDocument();
    expect(screen.getByText(/sshd\[1\]: Failed password for admin/, { selector: "pre" })).toBeInTheDocument();
    expect(api.getEvent).toHaveBeenCalledWith(1);
  });

  it("debounces the search box and resets paging", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    render(<Events />);
    await screen.findByText(/No events match/);
    const before = api.listEvents.mock.calls.length;
    await user.type(screen.getByPlaceholderText(/Search message/), "admin");
    await waitFor(() => expect(lastCallArgs(api.listEvents)).toMatchObject({ query: "admin", offset: 0 }));
    // five keystrokes must not produce five searches
    const searches = api.listEvents.mock.calls.slice(before).filter(([p]) => p.query);
    expect(searches.length).toBeLessThanOrEqual(2);
  });

  it("passes source, category and severity filters through", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    render(<Events />);
    await screen.findByText(/No events match/);
    const [source, category, severity] = screen.getAllByRole("combobox");
    await user.selectOptions(source, "windows");
    await user.selectOptions(category, "account_lockout");
    await user.selectOptions(severity, "high");
    await waitFor(() => expect(lastCallArgs(api.listEvents)).toMatchObject({ source: "windows", event_type: "account_lockout", severity: "high" }));
  });
});
