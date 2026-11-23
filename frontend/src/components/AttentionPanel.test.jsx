import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { alert, incident } from "../test/fixtures.js";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import AttentionPanel from "./AttentionPanel.jsx";

vi.mock("../services/api.js");

const iso = (minutesAgo) => new Date(Date.now() - minutesAgo * 60000).toISOString().slice(0, 19);

function setup({ critical = [], high = [], incidents = [] } = {}) {
  mockApiDefaults();
  vi.mocked(api.listAlerts).mockImplementation(async (p) =>
    ({ items: p.severity === "critical" ? critical : high, total: 0 }));
  vi.mocked(api.listIncidents).mockResolvedValue({ items: incidents, total: incidents.length });
  const props = { onOpenAlert: vi.fn(), onOpenIncident: vi.fn() };
  render(<AttentionPanel {...props} />);
  return props;
}

beforeEach(() => vi.clearAllMocks());

describe("AttentionPanel", () => {
  it("asks only for open critical and high alerts and open incidents", async () => {
    setup();
    await screen.findByText("Nothing needs attention");
    const calls = vi.mocked(api.listAlerts).mock.calls.map(([p]) => p);
    expect(calls).toEqual(expect.arrayContaining([
      expect.objectContaining({ status: "OPEN", severity: "critical" }),
      expect.objectContaining({ status: "OPEN", severity: "high" })]));
    expect(api.listIncidents).toHaveBeenCalledWith(expect.objectContaining({ status: "OPEN" }));
  });

  it("lists critical alerts before high ones, even when a high alert is newer", async () => {
    setup({
      critical: [alert({ id: 1, rule_name: "Old critical", severity: "critical", last_seen: iso(600) })],
      high: [alert({ id: 2, rule_name: "Fresh high", severity: "high", last_seen: iso(1) })],
    });
    await screen.findByText("Old critical");
    const rows = screen.getAllByRole("button").filter((b) => b.classList.contains("attention-row"));
    expect(rows.map((r) => within(r).getByText(/critical|high/i, { selector: ".title" }).textContent))
      .toEqual(["Old critical", "Fresh high"]);
  });

  it("shows the newest first within the same severity and never more than six alerts", async () => {
    setup({ critical: Array.from({ length: 8 }, (_, i) => alert({ id: i + 1, rule_name: `Crit ${i + 1}`, last_seen: iso(i + 1) })) });
    await screen.findByText("Crit 1");
    const titles = screen.getAllByRole("button").filter((b) => b.classList.contains("attention-row"))
      .map((r) => r.querySelector(".title").textContent);
    expect(titles).toEqual(["Crit 1", "Crit 2", "Crit 3", "Crit 4", "Crit 5", "Crit 6"]);
  });

  it("opens the alert or the incident that was clicked", async () => {
    const user = userEvent.setup();
    const props = setup({ critical: [alert({ id: 7, rule_name: "Brute force" })],
      incidents: [incident({ id: 3, incident_id: "INC-000003", title: "SSH story" })] });
    await user.click(await screen.findByText("Brute force"));
    expect(props.onOpenAlert).toHaveBeenCalledWith(7);
    await user.click(screen.getByText("SSH story"));
    expect(props.onOpenIncident).toHaveBeenCalledWith(3);
  });

  it("labels what each row is: severity, source, threat intel, age and incident size", async () => {
    setup({ critical: [alert({ id: 1, source_ip: "198.51.100.77", last_seen: iso(12),
      intel: { listed: true, feeds: [{ id: "demo", name: "Synthetic demo feed" }] } })],
      incidents: [incident({ alert_count: 3 })] });
    expect(await screen.findAllByText("Critical")).toHaveLength(2);  // the alert and the incident are both critical
    expect(screen.getByText(/198\.51\.100\.77/)).toBeInTheDocument();
    expect(screen.getByText("Known malicious")).toBeInTheDocument();
    expect(screen.getByText("12 min ago")).toBeInTheDocument();
    expect(screen.getByText(/INC-000001 · 3 alerts/)).toBeInTheDocument();
  });

  it("says plainly when nothing needs attention", async () => {
    setup();
    expect(await screen.findByText("Nothing needs attention")).toBeInTheDocument();
    expect(screen.getByText(/No open critical or high alerts/)).toBeInTheDocument();
  });

  it("shows a loading state first", () => {
    mockApiDefaults();
    vi.mocked(api.listAlerts).mockReturnValue(new Promise(() => {}));
    vi.mocked(api.listIncidents).mockReturnValue(new Promise(() => {}));
    render(<AttentionPanel onOpenAlert={() => {}} onOpenIncident={() => {}} />);
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });

  it("reports a failure without hiding what did load", async () => {
    mockApiDefaults();
    vi.mocked(api.listAlerts).mockRejectedValue(new Error("Request failed (500)"));
    vi.mocked(api.listIncidents).mockResolvedValue({ items: [incident({ title: "Still shown" })], total: 1 });
    render(<AttentionPanel onOpenAlert={() => {}} onOpenIncident={() => {}} />);
    expect(await screen.findByText(/Could not load data: Request failed \(500\)/)).toBeInTheDocument();
    expect(screen.getByText("Still shown")).toBeInTheDocument();
  });
});
