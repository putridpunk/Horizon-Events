import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import App from "../App.jsx";
import { routerFuture } from "../routerFuture.js";
import ImportButton from "../components/ImportButton.jsx";
import { alert, incident } from "../test/fixtures.js";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import Analytics from "./Analytics.jsx";
import Overview from "./Overview.jsx";
import Reports from "./Reports.jsx";

vi.mock("../services/api.js");
// Chart.js needs a real canvas; the charts themselves are not under test here.
vi.mock("../charts/charts.jsx", () => ({
  EventsOverTime: () => <div>chart:events-over-time</div>,
  SeverityDoughnut: () => <div>chart:severity</div>,
  HorizontalBars: () => <div>chart:bars</div>,
}));

describe("empty database", () => {
  it("Overview shows zeros and helpful empty states", async () => {
    mockApiDefaults();
    render(<Overview />);
    // The empty-state text is also shown while loading, so wait for the loaded zeros first.
    await waitFor(() => expect(screen.getAllByText("0")).toHaveLength(4));
    expect(screen.getByText("No events yet")).toBeInTheDocument();
    expect(await screen.findByText("Nothing needs attention")).toBeInTheDocument();
    expect(screen.queryByText(/Could not load data/)).not.toBeInTheDocument();
  });

  it("Analytics shows an empty state in every panel without crashing", async () => {
    mockApiDefaults();
    render(<Analytics />);
    // Each panel loads independently; wait for the ones whose text only appears once data has arrived.
    expect(await screen.findByText(/No model trained yet/)).toBeInTheDocument();
    expect(await screen.findByText(/No feeds loaded yet/)).toBeInTheDocument();
    await waitFor(() => expect(api.getRuleStats).toHaveBeenCalled());
    expect(screen.getByText(/Rule statistics appear after the first import/)).toBeInTheDocument();
    expect(screen.getAllByText("Nothing to show yet.").length).toBeGreaterThanOrEqual(4);
    expect(screen.queryByText(/chart:/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Could not load data/)).not.toBeInTheDocument();
  });

  it("Reports asks for a period before showing anything", async () => {
    mockApiDefaults();
    render(<Reports />);
    expect(screen.getByText(/click Generate to preview a report/)).toBeInTheDocument();
  });
});

describe("Overview with data", () => {
  it("shows counts, the chart and the latest alerts", async () => {
    mockApiDefaults();
    vi.mocked(api.getOverview).mockResolvedValue({ total_events: 56, total_alerts: 12, open_alerts: 12, critical_alerts: 1, high_alerts: 8, sources: 6 });
    vi.mocked(api.getTimeseries).mockResolvedValue([{ t: "2026-11-23T14:00:00", count: 20 }]);
    vi.mocked(api.listAlerts).mockImplementation(async (p) => ({ items: p.severity === "critical" ? [alert()] : [], total: 1 }));
    vi.mocked(api.listIncidents).mockResolvedValue({ items: [], total: 3 });
    render(<Overview />);
    expect(await screen.findByText("56")).toBeInTheDocument();
    expect(screen.getByText("chart:events-over-time")).toBeInTheDocument();
    expect(await screen.findByText("Repeated login failures")).toBeInTheDocument();
    expect(screen.getByText("Open alerts").parentElement).toHaveTextContent("12");
    expect(screen.getByText("Open incidents").parentElement).toHaveTextContent("3");
  });
});

describe("Reports", () => {
  const report = {
    total_events: 56, total_alerts: 12, first_event: "2026-11-23T08:00:00", last_event: "2026-11-23T23:40:12",
    top_event_types: [{ name: "authentication_failure", count: 27 }],
    severity_distribution: [{ severity: "critical", count: 1 }],
    techniques: [{ id: "T1110", name: "Brute Force", alerts: 7 }, { id: "T1489", name: "Service Stop", alerts: 0 }],
    incidents: { total: 7, by_status: { OPEN: 6, INVESTIGATING: 1, RESOLVED: 0 } },
  };

  it("previews a report with techniques that fired and incident counts, and links the downloads", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    vi.mocked(api.getReport).mockResolvedValue(report);
    render(<Reports />);
    await user.click(screen.getByRole("button", { name: "Generate" }));
    expect(await screen.findByText("Incidents (7)")).toBeInTheDocument();
    expect(screen.getByText(/T1110 Brute Force/)).toBeInTheDocument();
    expect(screen.queryByText(/T1489/)).not.toBeInTheDocument(); // techniques with no alerts are left out
    expect(screen.getByRole("button", { name: "Download CSV" }).closest("a")).toHaveAttribute("href", "/api/reports?format=csv");
  });

  it("makes the end date inclusive by asking for the following day", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    vi.mocked(api.getReport).mockResolvedValue(report);
    render(<Reports />);
    const [from, to] = document.querySelectorAll('input[type="date"]');
    await user.clear(from); await user.type(from, "2026-11-01");
    await user.clear(to); await user.type(to, "2026-11-30");
    await user.click(screen.getByRole("button", { name: "Generate" }));
    await waitFor(() => expect(api.getReport).toHaveBeenCalledWith("2026-11-01", "2026-12-01"));
  });

  it("does not crash when a date is cleared; it disables the actions and says why", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    render(<Reports />);
    const [, to] = document.querySelectorAll('input[type="date"]');
    await user.clear(to); // a cleared date input used to throw 'Invalid time value' while rendering
    expect(screen.getByText("Reports")).toBeInTheDocument();
    expect(screen.getByText(/Choose a valid date range/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Generate" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Download CSV" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Download CSV" }).closest("a")).toBeNull();
    expect(api.getReport).not.toHaveBeenCalled();
  });

  it("rejects a range whose start is after its end", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    render(<Reports />);
    const [from, to] = document.querySelectorAll('input[type="date"]');
    await user.clear(to); await user.type(to, "2026-01-01");
    await user.clear(from); await user.type(from, "2026-02-01");
    expect(screen.getByRole("button", { name: "Generate" })).toBeDisabled();
  });

  it("shows the server's message when the report fails", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    vi.mocked(api.getReport).mockRejectedValue(new Error("end must not be before start"));
    render(<Reports />);
    await user.click(screen.getByRole("button", { name: "Generate" }));
    expect(await screen.findByText(/end must not be before start/)).toBeInTheDocument();
  });
});

describe("ImportButton", () => {
  it("uploads the chosen file with the selected source type and reports the result", async () => {
    const user = userEvent.setup();
    const onDone = vi.fn();
    vi.mocked(api.importLogs).mockResolvedValue({ imported: 22, skipped: 1, duplicates: 0, alerts_created: 5 });
    const { container } = render(<ImportButton onDone={onDone} />);
    await user.selectOptions(screen.getByLabelText("Log source type"), "windows");
    const file = new File(["x"], "events.xml");
    await user.upload(container.querySelector('input[type="file"]'), file);
    expect(api.importLogs).toHaveBeenCalledWith(file, "windows");
    expect(await screen.findByText("22 imported, 1 skipped, 0 duplicates, 5 new alerts")).toBeInTheDocument();
    expect(onDone).toHaveBeenCalled();
  });

  it("shows the server's rejection (for example an oversized file)", async () => {
    const user = userEvent.setup();
    vi.mocked(api.importLogs).mockRejectedValue(new Error("File exceeds the 10 MB upload limit"));
    const { container } = render(<ImportButton />);
    await user.upload(container.querySelector('input[type="file"]'), new File(["x"], "big.log"));
    const message = await screen.findByText("File exceeds the 10 MB upload limit");
    expect(message.closest(".import-message")).toHaveClass("error");
  });
});

describe("App routing", () => {
  const at = (path) => render(<MemoryRouter initialEntries={[path]} future={routerFuture}><App /></MemoryRouter>);

  it("renders every page from its route and highlights the active nav link", async () => {
    mockApiDefaults();
    vi.mocked(api.listIncidents).mockResolvedValue({ items: [incident()], total: 1 });
    at("/incidents");
    expect(await screen.findByText("INC-000001")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Incidents" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "Alerts" })).not.toHaveClass("active");
  });

  it("falls back to the overview for unknown routes", async () => {
    mockApiDefaults();
    at("/nope");
    expect(await screen.findByText("Security overview")).toBeInTheDocument();
  });

  it("offers all six sections in the sidebar", async () => {
    mockApiDefaults();
    at("/");
    await screen.findByText("Security overview");
    for (const name of ["Overview", "Events", "Alerts", "Incidents", "Analytics", "Reports"]) {
      expect(screen.getByRole("link", { name })).toBeInTheDocument();
    }
  });
});
