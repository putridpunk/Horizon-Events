import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { alert, alertDetail, event, incident, incidentDetail } from "../test/fixtures.js";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import AlertDrawer from "../components/AlertDrawer.jsx";
import EventDetail from "../components/EventDetail.jsx";
import IncidentDrawer from "../components/IncidentDrawer.jsx";
import Alerts from "./Alerts.jsx";
import Events from "./Events.jsx";
import Incidents from "./Incidents.jsx";

vi.mock("../services/api.js");

describe("table rows are keyboard-accessible", () => {
  it("an alert row can be focused and opened with Enter, and closed again with Escape", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    vi.mocked(api.listAlerts).mockResolvedValue({ items: [alert()], total: 1 });
    vi.mocked(api.getAlert).mockResolvedValue(alertDetail());
    render(<Alerts />);
    const row = (await screen.findByText("ALT-000001")).closest("tr");
    expect(row).toHaveAttribute("tabindex", "0");
    row.focus();
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("dialog", { name: "ALT-000001" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(row).toHaveFocus();  // back where the user was
  });

  it("Space opens a row too", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    vi.mocked(api.listIncidents).mockResolvedValue({ items: [incident()], total: 1 });
    vi.mocked(api.getIncident).mockResolvedValue(incidentDetail());
    render(<Incidents />);
    const row = (await screen.findByText("INC-000001")).closest("tr");
    row.focus();
    await user.keyboard(" ");
    expect(await screen.findByRole("dialog", { name: "INC-000001" })).toBeInTheDocument();
  });

  it("an event row opens its detail dialog from the keyboard", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    vi.mocked(api.listEvents).mockResolvedValue({ items: [event()], total: 1 });
    vi.mocked(api.getEvent).mockResolvedValue(event());
    render(<Events />);
    const row = (await screen.findByText("Failed password for admin")).closest("tr");
    row.focus();
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("dialog", { name: "Event #1" })).toBeInTheDocument();
  });
});

describe("rows show the age of the item and a chevron", () => {
  it("alerts and incidents list a relative last-activity time with the exact time on hover", async () => {
    mockApiDefaults();
    const recent = new Date(Date.now() - 5 * 60000).toISOString().slice(0, 19);
    vi.mocked(api.listAlerts).mockResolvedValue({ items: [alert({ last_seen: recent })], total: 1 });
    const { container } = render(<Alerts />);
    expect(await screen.findByText("5 min ago")).toHaveAttribute("title", expect.stringMatching(/\d/));
    expect(container.querySelector("tbody tr td.chevron svg")).toBeInTheDocument();
  });
});

describe("Escape closes every drawer and dialog", () => {
  it.each([
    ["alert drawer", () => { vi.mocked(api.getAlert).mockResolvedValue(alertDetail()); return (onClose) => <AlertDrawer alertId={1} onClose={onClose} />; }],
    ["incident drawer", () => { vi.mocked(api.getIncident).mockResolvedValue(incidentDetail()); return (onClose) => <IncidentDrawer alertId={1} incidentId={1} others={[]} onClose={onClose} />; }],
    ["event dialog", () => (onClose) => <EventDetail event={event()} onClose={onClose} />],
  ])("%s", async (_name, build) => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(build()(onClose));
    await screen.findByRole("dialog");
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
