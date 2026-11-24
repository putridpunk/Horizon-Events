import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import Scan from "./Scan.jsx";

vi.mock("../services/api.js");

const ENABLED = { enabled: true, engine: "Microsoft Defender", available: true, message: "" };
const BAD = String.raw`C:\Users\me\Downloads\setup.exe`;
const GOOD = String.raw`C:\Users\me\Documents\notes.txt`;
const BROKEN = String.raw`C:\Users\me\locked.bin`;

function scan(over = {}) {
  return {
    id: 1, created_at: "2026-11-24T09:00:00", finished_at: "2026-11-24T09:00:05", status: "completed", error: null,
    targets: [GOOD], results: [{ path: GOOD, status: "clean", message: "", threats: [] }], done: 1, total: 1, threats: 0,
    ...over,
  };
}

function setup({ status = ENABLED, scans = [] } = {}) {
  mockApiDefaults();
  vi.mocked(api.getScanStatus).mockResolvedValue(status);
  vi.mocked(api.listScans).mockResolvedValue({ items: scans });
  vi.mocked(api.startScan).mockResolvedValue(scan({ status: "running" }));
  return render(<MemoryRouter><Scan /></MemoryRouter>);
}

function withPicker(api_) {
  window.pywebview = { api: api_ };
}

afterEach(() => {
  delete window.pywebview;
});

describe("Scan files", () => {
  it("says scanning is desktop-only when the server has it switched off", async () => {
    setup({ status: { ...ENABLED, enabled: false, available: false, message: "File scanning is only available in the desktop app." } });
    expect(await screen.findByText(/only available in the desktop app/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Choose files/ })).not.toBeInTheDocument();
  });

  it("explains that nothing is uploaded or deleted and that detections become alerts", async () => {
    setup();
    expect(await screen.findByText(/Nothing is uploaded, moved\s+or deleted/)).toBeInTheDocument();
    expect(screen.getByText(/becomes a critical alert/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Choose files/ })).toBeEnabled();
  });

  it("disables scanning and says why when Defender is missing", async () => {
    setup({ status: { ...ENABLED, available: false, message: "Microsoft Defender was not found on this computer." } });
    expect(await screen.findByRole("alert")).toHaveTextContent("Defender was not found");
    expect(screen.getByRole("button", { name: /Choose files/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Choose folder/ })).toBeDisabled();
  });

  it("starts a scan of the files chosen in the native picker", async () => {
    setup();
    withPicker({ pick_files: vi.fn().mockResolvedValue([BAD, GOOD]), pick_folder: vi.fn() });
    await userEvent.click(await screen.findByRole("button", { name: /Choose files/ }));
    await waitFor(() => expect(api.startScan).toHaveBeenCalledWith([BAD, GOOD]));
  });

  it("starts a scan of a chosen folder", async () => {
    setup();
    withPicker({ pick_files: vi.fn(), pick_folder: vi.fn().mockResolvedValue([String.raw`C:\Users\me\Downloads`]) });
    await userEvent.click(await screen.findByRole("button", { name: /Choose folder/ }));
    await waitFor(() => expect(api.startScan).toHaveBeenCalledWith([String.raw`C:\Users\me\Downloads`]));
  });

  it("does nothing when the picker is cancelled", async () => {
    setup();
    const pick = vi.fn().mockResolvedValue([]);
    withPicker({ pick_files: pick, pick_folder: vi.fn() });
    await userEvent.click(await screen.findByRole("button", { name: /Choose files/ }));
    await waitFor(() => expect(pick).toHaveBeenCalled());
    expect(api.startScan).not.toHaveBeenCalled();
  });

  it("tells the user when the picker is not available (opened in a browser)", async () => {
    setup();
    await userEvent.click(await screen.findByRole("button", { name: /Choose files/ }));
    expect(await screen.findByText(/file picker is not available here/)).toBeInTheDocument();
    expect(api.startScan).not.toHaveBeenCalled();
  });

  it("shows the server's message when the scan is refused", async () => {
    setup();
    vi.mocked(api.startScan).mockRejectedValue(new Error("A scan is already running."));
    withPicker({ pick_files: vi.fn().mockResolvedValue([GOOD]), pick_folder: vi.fn() });
    await userEvent.click(await screen.findByRole("button", { name: /Choose files/ }));
    expect(await screen.findByText("A scan is already running.")).toBeInTheDocument();
  });

  it("shows each result: threat with its name, clean, and an item that could not be scanned", async () => {
    setup({
      scans: [scan({
        targets: [BAD, GOOD, BROKEN], done: 3, total: 3, threats: 1,
        results: [
          { path: BAD, status: "threat", message: "", threats: [{ threat: "Virus:DOS/EICAR_Test_File", path: BAD, sha256: "ab", alert_id: 7 }] },
          { path: GOOD, status: "clean", message: "", threats: [] },
          { path: BROKEN, status: "error", message: "Access denied", threats: [] },
        ],
      })],
    });
    expect(await screen.findByText("1 threat found")).toBeInTheDocument();
    const rows = screen.getAllByRole("row");
    expect(within(rows[1]).getByText("Threat found")).toBeInTheDocument();
    expect(within(rows[1]).getByText("Virus:DOS/EICAR_Test_File")).toBeInTheDocument();
    expect(within(rows[2]).getByText("Clean")).toBeInTheDocument();
    expect(within(rows[3]).getByText("Could not scan")).toBeInTheDocument();
    expect(within(rows[3]).getByText("Access denied")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View alerts" })).toHaveAttribute("href", "/alerts");
  });

  it("reports a clean scan plainly, and never calls an unscanned item clean", async () => {
    setup({ scans: [scan()] });
    expect(await screen.findByText("No threats found")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "View alerts" })).not.toBeInTheDocument();
  });

  it("says so when some items could not be scanned even though no threat was found", async () => {
    setup({ scans: [scan({ targets: [BROKEN], results: [{ path: BROKEN, status: "error", message: "x", threats: [] }] })] });
    expect(await screen.findByText(/No threats found, 1 item could not be scanned/)).toBeInTheDocument();
  });

  it("shows progress while a scan runs and blocks starting another", async () => {
    setup({ scans: [scan({ status: "running", finished_at: null, targets: [GOOD, BAD, BROKEN], results: [{ path: GOOD, status: "clean", message: "", threats: [] }], done: 1, total: 3 })] });
    expect(await screen.findByText("Scanning 2 of 3…")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Choose files/ })).toBeDisabled();
    expect(screen.getAllByText("Waiting…")).toHaveLength(2);
  });

  it("shows why a scan stopped", async () => {
    setup({ scans: [scan({ status: "failed", error: "The app was closed during the scan." })] });
    expect(await screen.findByText(/The scan stopped: The app was closed/)).toBeInTheDocument();
  });

  it("lists earlier scans below the latest", async () => {
    setup({ scans: [scan({ id: 2 }), scan({ id: 1, threats: 2, results: [], done: 1 })] });
    expect(await screen.findByText("Earlier scans")).toBeInTheDocument();
    expect(screen.getByText("2 threats found")).toBeInTheDocument();
  });
});
