import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import AlertDrawer from "../components/AlertDrawer.jsx";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import Settings from "./Settings.jsx";

vi.mock("../services/api.js");

const ALERT = {
  id: 5, alert_id: "ALT-000005", rule_id: "HZ-001", rule_name: "Repeated login failures", severity: "high", status: "OPEN",
  description: "d", source_ip: "8.8.4.4", username: "admin", occurrences: 3, window_minutes: 5, techniques: [],
  created_at: "2026-11-24T09:00:00", last_seen: "2026-11-24T09:00:00", intel: null, events: [], history: [],
};

function drawer(alert = ALERT) {
  mockApiDefaults();
  vi.mocked(api.getAlert).mockResolvedValue(alert);
  return render(<MemoryRouter><AlertDrawer alertId={5} onClose={() => {}} /></MemoryRouter>);
}

describe("Suppress from an alert", () => {
  it("asks for confirmation and says exactly what will be hidden", async () => {
    drawer();
    await userEvent.click(await screen.findByRole("button", { name: /Suppress similar alerts/ }));
    const group = screen.getByRole("group", { name: "Confirm suppression" });
    expect(group).toHaveTextContent("HZ-001 for 8.8.4.4 and account admin");
    expect(group).toHaveTextContent("undo this in Settings");
    expect(api.suppressAlert).not.toHaveBeenCalled();
  });

  it("suppresses only after confirming", async () => {
    drawer();
    vi.mocked(api.suppressAlert).mockResolvedValue({ id: 1 });
    await userEvent.click(await screen.findByRole("button", { name: /Suppress similar alerts/ }));
    await userEvent.click(screen.getByRole("button", { name: "Suppress and resolve" }));
    await waitFor(() => expect(api.suppressAlert).toHaveBeenCalledWith(5));
  });

  it("can be cancelled", async () => {
    drawer();
    await userEvent.click(await screen.findByRole("button", { name: /Suppress similar alerts/ }));
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("group", { name: "Confirm suppression" })).not.toBeInTheDocument();
    expect(api.suppressAlert).not.toHaveBeenCalled();
  });

  it("shows the server's message when suppressing fails", async () => {
    drawer();
    vi.mocked(api.suppressAlert).mockRejectedValue(new Error("Malware detections cannot be suppressed."));
    await userEvent.click(await screen.findByRole("button", { name: /Suppress similar alerts/ }));
    await userEvent.click(screen.getByRole("button", { name: "Suppress and resolve" }));
    expect(await screen.findByText("Malware detections cannot be suppressed.")).toBeInTheDocument();
  });

  it("does not offer suppression for malware alerts", async () => {
    drawer({ ...ALERT, rule_id: "HZ-008", source_ip: null, username: null });
    await screen.findByText("ALT-000005");
    expect(screen.queryByRole("button", { name: /Suppress similar alerts/ })).not.toBeInTheDocument();
  });
});

describe("Settings page: suppressed alerts", () => {
  const ITEM = { id: 3, rule_id: "HZ-001", source_ip: "8.8.4.4", username: null, note: "backup job", created_at: "2026-11-24T09:00:00", hits: 12, last_hit: null };

  function page(items) {
    mockApiDefaults();
    vi.mocked(api.listSuppressions).mockResolvedValue({ items });
    return render(<MemoryRouter><Settings /></MemoryRouter>);
  }

  it("says when nothing is suppressed", async () => {
    page([]);
    expect(await screen.findByText("Nothing is suppressed.")).toBeInTheDocument();
  });

  it("lists what each suppression matches, its note and how many alerts it silenced", async () => {
    page([ITEM]);
    expect(await screen.findByText("rule HZ-001, address 8.8.4.4")).toBeInTheDocument();
    expect(screen.getByText("backup job")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
  });

  it("removes a suppression", async () => {
    page([ITEM]);
    vi.mocked(api.deleteSuppression).mockResolvedValue({ deleted: 3 });
    await userEvent.click(await screen.findByRole("button", { name: /Remove suppression for rule HZ-001/ }));
    await waitFor(() => expect(api.deleteSuppression).toHaveBeenCalledWith(3));
  });
});
