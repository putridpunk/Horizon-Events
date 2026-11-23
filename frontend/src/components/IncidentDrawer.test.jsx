import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { incident, incidentDetail } from "../test/fixtures.js";
import * as api from "../services/api.js";
import IncidentDrawer from "./IncidentDrawer.jsx";

vi.mock("../services/api.js");

const OTHERS = [incident({ id: 3, incident_id: "INC-000003", title: "Unknown users from 203.0.113.7" })];

function setup({ detail = incidentDetail(), others = OTHERS } = {}) {
  vi.mocked(api.getIncident).mockResolvedValue(detail);
  const props = { incidentId: 1, others, onClose: vi.fn(), onChanged: vi.fn() };
  render(<IncidentDrawer {...props} />);
  return props;
}

describe("IncidentDrawer", () => {
  it("summarises the incident: IPs, accounts, techniques, alerts, intel and audit trail", async () => {
    setup();
    expect(await screen.findByText("INC-000001")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.15", { selector: "dd" })).toBeInTheDocument();
    expect(screen.getByText("admin", { selector: "dd" })).toBeInTheDocument();
    expect(screen.getByText("Alerts (2)")).toBeInTheDocument();
    expect(screen.getByText("Known malicious")).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "T1110" }).length).toBeGreaterThan(0);
    expect(screen.getByText("Opened")).toBeInTheDocument();
    expect(screen.getByText(/does not mean a breach is confirmed/)).toBeInTheDocument();
  });

  it("removes the chosen alert and reloads", async () => {
    const user = userEvent.setup();
    const props = setup();
    vi.mocked(api.removeIncidentAlert).mockResolvedValue({});
    const rows = (await screen.findAllByRole("button", { name: "Remove" }));
    expect(rows).toHaveLength(2);
    await user.click(rows[1]);
    expect(api.removeIncidentAlert).toHaveBeenCalledWith(1, 5);
    await waitFor(() => expect(props.onChanged).toHaveBeenCalled());
    expect(api.getIncident).toHaveBeenCalledTimes(2);
  });

  it("changes status with the typed note", async () => {
    const user = userEvent.setup();
    setup();
    vi.mocked(api.updateIncident).mockResolvedValue({});
    await user.type(await screen.findByPlaceholderText(/Add a note/), "paged the on-call");
    await user.click(screen.getByRole("button", { name: "Start investigation" }));
    expect(api.updateIncident).toHaveBeenCalledWith(1, { status: "INVESTIGATING", note: "paged the on-call" });
  });

  it("enables 'Add note only' and 'Rename' only when there is text", async () => {
    const user = userEvent.setup();
    setup();
    vi.mocked(api.addIncidentNote).mockResolvedValue({});
    vi.mocked(api.updateIncident).mockResolvedValue({});
    const addNote = await screen.findByRole("button", { name: "Add note only" });
    const rename = screen.getByRole("button", { name: "Rename" });
    expect(addNote).toBeDisabled();
    expect(rename).toBeDisabled();
    await user.type(screen.getByPlaceholderText(/Add a note/), "called owner");
    await user.click(addNote);
    expect(api.addIncidentNote).toHaveBeenCalledWith(1, "called owner");
    await user.type(screen.getByPlaceholderText("Rename incident"), "SSH brute force");
    await user.click(rename);
    expect(api.updateIncident).toHaveBeenCalledWith(1, { title: "SSH brute force" });
  });

  it("merges into another open incident", async () => {
    const user = userEvent.setup();
    setup();
    vi.mocked(api.mergeIncident).mockResolvedValue({});
    const select = await screen.findByRole("combobox");
    expect(within(select).getByRole("option", { name: /INC-000003/ })).toBeInTheDocument();
    const merge = screen.getByRole("button", { name: "Merge" });
    expect(merge).toBeDisabled();
    await user.selectOptions(select, "3");
    await user.click(merge);
    expect(api.mergeIncident).toHaveBeenCalledWith(1, 3);
  });

  it("hides merging for a resolved incident or when there is nothing to merge into", async () => {
    setup({ detail: incidentDetail({ status: "RESOLVED" }) });
    expect(await screen.findByText("INC-000001")).toBeInTheDocument();
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reopen" })).toBeInTheDocument();
  });

  it("shows the server error when an action fails", async () => {
    const user = userEvent.setup();
    const props = setup();
    vi.mocked(api.updateIncident).mockRejectedValue(new Error("Cannot merge into a resolved incident"));
    await user.click(await screen.findByRole("button", { name: "Resolve" }));
    expect(await screen.findByText("Cannot merge into a resolved incident")).toBeInTheDocument();
    expect(props.onChanged).not.toHaveBeenCalled();
  });
});
