import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import Settings from "./Settings.jsx";

vi.mock("../services/api.js");

const STATUS = { backups_available: true, retention_days: 0, events: 12345, oldest_event: "2026-01-02T10:00:00", database_bytes: 5 * 1024 * 1024, restore_pending: false };

function page(status = STATUS) {
  mockApiDefaults();
  vi.mocked(api.getDataStatus).mockResolvedValue(status);
  vi.mocked(api.setRetention).mockResolvedValue(status);
  vi.mocked(api.purgeOldEvents).mockResolvedValue({ removed: 7, ...status });
  vi.mocked(api.backupData).mockResolvedValue({ path: String.raw`C:\Backups\b.hzbackup`, bytes: 10 });
  vi.mocked(api.restoreData).mockResolvedValue({ restart_required: true });
  vi.mocked(api.cancelRestore).mockResolvedValue({ restore_pending: false });
  return render(<MemoryRouter><Settings /></MemoryRouter>);
}

afterEach(() => {
  delete window.pywebview;
});

describe("Data settings", () => {
  it("shows how much is stored", async () => {
    page();
    expect(await screen.findByText(/12\D?345 events stored \(5\.0 MB\)/)).toBeInTheDocument();
  });

  it("saves a retention period and says that evidence for alerts is kept", async () => {
    page();
    await userEvent.selectOptions(await screen.findByLabelText("Delete old events after"), "90");
    await waitFor(() => expect(api.setRetention).toHaveBeenCalledWith(90));
    expect(screen.getByText(/belong to an alert are always kept/)).toBeInTheDocument();
  });

  it("cleans up on demand and reports the count, but not when retention is off", async () => {
    page({ ...STATUS, retention_days: 30 });
    await userEvent.click(await screen.findByRole("button", { name: "Clean up now" }));
    expect(await screen.findByText("Removed 7 old events.")).toBeInTheDocument();
  });

  it("disables the clean-up button when everything is kept", async () => {
    page();
    expect(await screen.findByRole("button", { name: "Clean up now" })).toBeDisabled();
  });

  it("backs up to the file chosen in the native dialog", async () => {
    page();
    window.pywebview = { api: { pick_save_file: vi.fn().mockResolvedValue(String.raw`C:\Backups\b.hzbackup`), pick_file: vi.fn() } };
    await userEvent.click(await screen.findByRole("button", { name: "Back up data…" }));
    await waitFor(() => expect(api.backupData).toHaveBeenCalledWith(String.raw`C:\Backups\b.hzbackup`));
    expect(await screen.findByText(/Backup saved to/)).toBeInTheDocument();
  });

  it("does nothing when the dialog is cancelled", async () => {
    page();
    window.pywebview = { api: { pick_save_file: vi.fn().mockResolvedValue(""), pick_file: vi.fn().mockResolvedValue("") } };
    await userEvent.click(await screen.findByRole("button", { name: "Back up data…" }));
    await userEvent.click(screen.getByRole("button", { name: "Restore from backup…" }));
    await waitFor(() => expect(window.pywebview.api.pick_file).toHaveBeenCalled());
    expect(api.backupData).not.toHaveBeenCalled();
    expect(api.restoreData).not.toHaveBeenCalled();
  });

  it("stages a restore and tells the user to restart", async () => {
    page();
    window.pywebview = { api: { pick_save_file: vi.fn(), pick_file: vi.fn().mockResolvedValue(String.raw`C:\Backups\b.hzbackup`) } };
    await userEvent.click(await screen.findByRole("button", { name: "Restore from backup…" }));
    await waitFor(() => expect(api.restoreData).toHaveBeenCalledWith(String.raw`C:\Backups\b.hzbackup`));
    expect(await screen.findByText(/Close and reopen it to finish/)).toBeInTheDocument();
  });

  it("shows a waiting restore and lets it be cancelled", async () => {
    page({ ...STATUS, restore_pending: true });
    await userEvent.click(await screen.findByRole("button", { name: "Cancel the restore" }));
    await waitFor(() => expect(api.cancelRestore).toHaveBeenCalled());
  });

  it("explains when the dialogs are not available", async () => {
    page();
    await userEvent.click(await screen.findByRole("button", { name: "Back up data…" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("desktop window");
  });

  it("says backups are desktop-only otherwise", async () => {
    page({ ...STATUS, backups_available: false });
    expect(await screen.findByText(/Backups are only available in the desktop app/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Back up data…" })).not.toBeInTheDocument();
  });

  it("shows the server's message when something fails", async () => {
    page();
    vi.mocked(api.setRetention).mockRejectedValue(new Error("Keep events for 0 (forever) to 3650 days."));
    await userEvent.selectOptions(await screen.findByLabelText("Delete old events after"), "30");
    expect(await screen.findByRole("alert")).toHaveTextContent("3650 days");
  });
});
