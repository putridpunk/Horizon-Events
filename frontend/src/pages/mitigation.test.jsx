import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import MitigationPanel from "../components/MitigationPanel.jsx";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import Mitigation from "./Mitigation.jsx";

vi.mock("../services/api.js");

const ADVICE = ["Check whether the failed sign-ins were really you.", "Block the source IP."];

function action(over = {}) {
  return {
    id: 1, alert_id: 5, kind: "block_ip", target: "8.8.4.4", status: "suggested", automatic: false,
    created_at: "2026-11-24T09:00:00", finished_at: null, expires_at: null, expired: false, message: "", sha256: null, ...over,
  };
}

function panel(data) {
  mockApiDefaults();
  vi.mocked(api.getAlertMitigation).mockResolvedValue({ enabled: true, advice: ADVICE, actions: [], skipped: [], ...data });
  return render(<MitigationPanel alertId={5} />);
}

describe("Recommended steps panel", () => {
  it("always lists the advice, even when actions are not available", async () => {
    panel({ enabled: false, actions: [action()] });
    expect(await screen.findByText("Block the source IP.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Approve block/ })).not.toBeInTheDocument();
  });

  it("offers a block for approval and explains the Windows prompt", async () => {
    panel({ actions: [action()] });
    expect(await screen.findByText("Block 8.8.4.4 in Windows Firewall")).toBeInTheDocument();
    expect(screen.getByText(/Windows will ask for your permission/)).toBeInTheDocument();
    expect(screen.getByText("Waiting for you")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Approve block" }));
    await waitFor(() => expect(api.approveMitigation).toHaveBeenCalledWith(1));
  });

  it("dismisses a proposal", async () => {
    panel({ actions: [action()] });
    await userEvent.click(await screen.findByRole("button", { name: "Dismiss" }));
    await waitFor(() => expect(api.dismissMitigation).toHaveBeenCalledWith(1));
  });

  it("offers to quarantine a file and shows its path", async () => {
    panel({ actions: [action({ id: 2, kind: "quarantine_file", target: String.raw`C:\Users\me\evil.exe`})] });
    expect(await screen.findByText("Move the file to quarantine")).toBeInTheDocument();
    expect(screen.getByText(String.raw`C:\Users\me\evil.exe`)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Quarantine file" })).toBeInTheDocument();
  });

  it("shows progress while an action runs, with no buttons", async () => {
    panel({ actions: [action({ status: "running", message: "Waiting for you in the Windows permission prompt…" })] });
    expect(await screen.findByRole("status")).toHaveTextContent("Windows permission prompt");
    expect(screen.queryByRole("button", { name: /Approve|Dismiss/ })).not.toBeInTheDocument();
  });

  it("lets a finished block be removed, and a finished quarantine be restored", async () => {
    panel({ actions: [action({ status: "done", message: "Blocked until 2026-12-01." }),
                      action({ id: 2, kind: "quarantine_file", target: "C:/x", status: "done", automatic: true, message: "Moved to quarantine." })] });
    await userEvent.click(await screen.findByRole("button", { name: "Remove block" }));
    await waitFor(() => expect(api.undoMitigation).toHaveBeenCalledWith(1));
    expect(screen.getByRole("button", { name: "Restore file" })).toBeInTheDocument();
    expect(screen.getByText("Done automatically")).toBeInTheDocument();
    expect(screen.getByText("Blocked until 2026-12-01.")).toBeInTheDocument();
  });

  it("flags an expired block", async () => {
    panel({ actions: [action({ status: "done", expired: true })] });
    expect(await screen.findByText("Expired: remove it")).toBeInTheDocument();
  });

  it("shows why a failed action did not work and allows another try", async () => {
    panel({ actions: [action({ status: "failed", message: "Windows permission was not granted." })] });
    expect(await screen.findByText("Windows permission was not granted.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("hides dismissed proposals and explains skipped ones", async () => {
    panel({ actions: [action({ status: "dismissed" })], skipped: [{ kind: "block_ip", target: "192.168.1.50", reason: "This is a private-network address." }] });
    expect(await screen.findByText(/Not suggested \(192.168.1.50\): This is a private-network address./)).toBeInTheDocument();
    expect(screen.queryByText("Dismissed")).not.toBeInTheDocument();
  });

  it("shows the server's message when an action is refused", async () => {
    panel({ actions: [action()] });
    vi.mocked(api.approveMitigation).mockRejectedValue(new Error("This action is already running."));
    await userEvent.click(await screen.findByRole("button", { name: "Approve block" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("already running");
  });
});

describe("Mitigation page", () => {
  const SETTINGS = { enabled: true, block_ip: "ask", quarantine_file: "ask", block_private: false, block_days: 7, allowlist: ["10.0.0.0/8"] };

  function page(settings = SETTINGS, items = []) {
    mockApiDefaults();
    vi.mocked(api.getMitigationSettings).mockResolvedValue(settings);
    vi.mocked(api.getMitigationHistory).mockResolvedValue({ items });
    vi.mocked(api.updateMitigationSettings).mockResolvedValue(settings);
    return render(<MemoryRouter><Mitigation /></MemoryRouter>);
  }

  it("says actions are desktop-only when disabled", async () => {
    page({ ...SETTINGS, enabled: false });
    expect(await screen.findByText(/only available in the desktop app/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save settings" })).not.toBeInTheDocument();
  });

  it("shows the current settings and offers Automatic only for quarantine", async () => {
    page();
    const block = await screen.findByLabelText(/Block attacking addresses/);
    expect(block).toHaveValue("ask");
    expect(within(block).queryByRole("option", { name: /Automatic/ })).not.toBeInTheDocument();
    expect(within(screen.getByLabelText(/Quarantine malware/)).getByRole("option", { name: /Automatic/ })).toBeInTheDocument();
    expect(screen.getByLabelText(/Never block these addresses/)).toHaveValue("10.0.0.0/8");
    expect(screen.getByLabelText(/Allow blocking private-network addresses/)).not.toBeChecked();
  });

  it("saves changed settings, one allowlist entry per line", async () => {
    page();
    await userEvent.selectOptions(await screen.findByLabelText(/Quarantine malware/), "auto");
    await userEvent.clear(screen.getByLabelText(/Never block these addresses/));
    await userEvent.type(screen.getByLabelText(/Never block these addresses/), "8.8.4.4{enter}192.168.1.0/24");
    await userEvent.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(api.updateMitigationSettings).toHaveBeenCalledWith({
      block_ip: "ask", quarantine_file: "auto", block_private: false, block_days: 7, allowlist: ["8.8.4.4", "192.168.1.0/24"],
    }));
    expect(await screen.findByText("Saved.")).toBeInTheDocument();
  });

  it("shows the server's message when settings are rejected", async () => {
    page();
    vi.mocked(api.updateMitigationSettings).mockRejectedValue(new Error("Not an IP address or range: banana"));
    await userEvent.click(await screen.findByRole("button", { name: "Save settings" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("banana");
  });

  it("lists the history and undoes a finished action", async () => {
    page(SETTINGS, [
      action({ id: 7, status: "done", message: "Blocked until 2026-12-01.", expired: true }),
      action({ id: 8, kind: "quarantine_file", target: "C:/evil.exe", status: "undone" }),
    ]);
    expect(await screen.findByText("Blocked until 2026-12-01.")).toBeInTheDocument();
    expect(screen.getByText(/expired/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Remove block" }));
    await waitFor(() => expect(api.undoMitigation).toHaveBeenCalledWith(7));
    expect(screen.getAllByRole("button", { name: /Remove block|Restore file/ })).toHaveLength(1);
  });

  it("explains an empty history", async () => {
    page();
    expect(await screen.findByText(/No actions yet/)).toBeInTheDocument();
  });
});
