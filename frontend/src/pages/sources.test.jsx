import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import App from "../App.jsx";
import { collector } from "../test/fixtures.js";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import Setup from "./Setup.jsx";
import Sources from "./Sources.jsx";

vi.mock("../services/api.js");

const SECURITY = collector({ id: "windows-security", name: "Windows Security log", access: "needs_permission",
  description: "Sign-in activity: failed and successful logons." });
const SYSTEM = collector({ id: "windows-system", name: "Windows System log" });
const APPLICATION = collector({ id: "windows-application", name: "Windows Application log" });

function withCollectors(items, over = {}) {
  mockApiDefaults();
  vi.mocked(api.getCollectors).mockResolvedValue({ enabled: true, platform: "windows", items, ...over });
}

function renderSetup() {
  return render(
    <MemoryRouter initialEntries={["/setup"]}>
      <Routes>
        <Route path="/setup" element={<Setup />} />
        <Route path="/" element={<div>home page</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("Setup screen", () => {
  it("explains what is read, that it stays on this machine, and lists every source with its state", async () => {
    withCollectors([SYSTEM, APPLICATION, SECURITY]);
    renderSetup();
    expect(await screen.findByText("Windows Security log")).toBeInTheDocument();
    expect(screen.getByText(/Everything stays on this machine/)).toBeInTheDocument();
    expect(screen.getByText(/no\s+account is needed/)).toBeInTheDocument();
    expect(screen.getAllByText("Off")).toHaveLength(2);
    expect(screen.getByText("Needs permission")).toBeInTheDocument();
  });

  it("preselects the sources that exist, and 'Start collecting' enables them then finishes setup", async () => {
    const user = userEvent.setup();
    withCollectors([SYSTEM, APPLICATION, collector({ id: "windows-security", access: "unavailable", name: "Sec" })]);
    vi.mocked(api.updateCollector).mockResolvedValue({});
    vi.mocked(api.completeSetup).mockResolvedValue({});
    renderSetup();
    await screen.findByText("Windows System log");
    expect(screen.getByLabelText("Collect Sec")).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Start collecting" }));
    await waitFor(() => expect(api.completeSetup).toHaveBeenCalledTimes(1));
    expect(api.updateCollector).toHaveBeenCalledWith("windows-system", { enabled: true, backfill_hours: 0 });
    expect(api.updateCollector).toHaveBeenCalledWith("windows-application", { enabled: true, backfill_hours: 0 });
    expect(api.updateCollector).toHaveBeenCalledTimes(2)  // the unavailable one is left alone
    expect(await screen.findByText("home page")).toBeInTheDocument();
  });

  it("honours unticked sources and the 24-hour backfill option", async () => {
    const user = userEvent.setup();
    withCollectors([SYSTEM, APPLICATION]);
    vi.mocked(api.updateCollector).mockResolvedValue({});
    vi.mocked(api.completeSetup).mockResolvedValue({});
    renderSetup();
    await screen.findByText("Windows System log");
    await user.click(screen.getByLabelText("Collect Windows Application log"));
    await user.click(screen.getByLabelText(/Also read the last 24 hours/));
    await user.click(screen.getByRole("button", { name: "Start collecting" }));
    await waitFor(() => expect(api.completeSetup).toHaveBeenCalled());
    expect(api.updateCollector).toHaveBeenCalledTimes(1);
    expect(api.updateCollector).toHaveBeenCalledWith("windows-system", { enabled: true, backfill_hours: 24 });
  });

  it("'Set up later' finishes without enabling anything", async () => {
    const user = userEvent.setup();
    withCollectors([SYSTEM]);
    vi.mocked(api.completeSetup).mockResolvedValue({});
    renderSetup();
    await user.click(await screen.findByRole("button", { name: "Set up later" }));
    await waitFor(() => expect(api.completeSetup).toHaveBeenCalled());
    expect(api.updateCollector).not.toHaveBeenCalled();
  });

  it("shows the server's message and stays put when saving fails", async () => {
    const user = userEvent.setup();
    withCollectors([SYSTEM]);
    vi.mocked(api.updateCollector).mockRejectedValue(new Error("database is locked"));
    renderSetup();
    await screen.findByText("Windows System log");
    await user.click(screen.getByRole("button", { name: "Start collecting" }));
    expect(await screen.findByText("database is locked")).toBeInTheDocument();
    expect(api.completeSetup).not.toHaveBeenCalled();
    expect(screen.queryByText("home page")).not.toBeInTheDocument();
  });

  it("says collection is unavailable in server mode and disables Start", async () => {
    withCollectors([], { enabled: false });
    renderSetup();
    expect(await screen.findByText(/not available in this mode/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start collecting" })).toBeDisabled();
  });
});

describe("Enable access (Security log)", () => {
  it("names exactly what will happen and only asks Windows after the user confirms", async () => {
    const user = userEvent.setup();
    withCollectors([SECURITY]);
    vi.mocked(api.enableSecurityAccess).mockResolvedValue({ requested: true, access: "needs_permission" });
    renderSetup();
    await user.click(await screen.findByRole("button", { name: "Enable access" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/Event Log Readers/)).toBeInTheDocument();
    expect(within(dialog).getByText(/Windows will show its own\s+permission prompt/)).toBeInTheDocument();
    expect(within(dialog).getByText(/sign out of Windows and\s+back in once/)).toBeInTheDocument();
    expect(api.enableSecurityAccess).not.toHaveBeenCalled();  // opening the dialog changes nothing
    await user.click(within(dialog).getByRole("button", { name: "Continue" }));
    expect(api.enableSecurityAccess).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(/sign out of Windows and back in one time/)).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("Cancel does nothing", async () => {
    const user = userEvent.setup();
    withCollectors([SECURITY]);
    renderSetup();
    await user.click(await screen.findByRole("button", { name: "Enable access" }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(api.enableSecurityAccess).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("reports a declined Windows prompt honestly", async () => {
    const user = userEvent.setup();
    withCollectors([SECURITY]);
    vi.mocked(api.enableSecurityAccess).mockResolvedValue({ requested: false, access: "needs_permission" });
    renderSetup();
    await user.click(await screen.findByRole("button", { name: "Enable access" }));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByText(/not approved, so nothing was changed/)).toBeInTheDocument();
  });

  it("shows the server's error if the request fails", async () => {
    const user = userEvent.setup();
    withCollectors([SECURITY]);
    vi.mocked(api.enableSecurityAccess).mockRejectedValue(new Error("Could not determine your Windows account."));
    renderSetup();
    await user.click(await screen.findByRole("button", { name: "Enable access" }));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByText("Could not determine your Windows account.")).toBeInTheDocument();
  });

  it("tells the user to sign out and in while waiting, and offers no button then", async () => {
    withCollectors([collector({ ...SECURITY, access: "waiting_signout", state: "waiting_signout" })]);
    renderSetup();
    expect(await screen.findByText("Waiting for sign-out")).toBeInTheDocument();
    expect(screen.getByText(/Sign out of Windows and back in once/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Enable access" })).not.toBeInTheDocument();
  });
});

describe("Data sources page", () => {
  it("shows each source's state, counts, last event and last error", async () => {
    withCollectors([
      collector({ ...SYSTEM, enabled: true, state: "collecting", events_read: 12, last_activity: "2026-11-23T14:21:20" }),
      collector({ ...APPLICATION, enabled: true, state: "collecting", last_error: "wevtutil exited with code 1" }),
    ]);
    render(<Sources />);
    expect(await screen.findByText("12 events read", { exact: false })).toBeInTheDocument();
    expect(screen.getAllByText("Collecting")).toHaveLength(2);
    expect(screen.getByText("wevtutil exited with code 1")).toBeInTheDocument();
    expect(screen.getByText(/last event none yet/)).toBeInTheDocument();
  });

  it("toggling a source saves immediately, and Check access re-checks it", async () => {
    const user = userEvent.setup();
    withCollectors([SYSTEM]);
    vi.mocked(api.updateCollector).mockResolvedValue({});
    vi.mocked(api.checkCollector).mockResolvedValue({});
    render(<Sources />);
    await user.click(await screen.findByLabelText("Collect Windows System log"));
    expect(api.updateCollector).toHaveBeenCalledWith("windows-system", { enabled: true });
    await user.click(screen.getByRole("button", { name: "Check access" }));
    expect(api.checkCollector).toHaveBeenCalledWith("windows-system");
  });

  it("shows an action error without losing the list", async () => {
    const user = userEvent.setup();
    withCollectors([SYSTEM]);
    vi.mocked(api.updateCollector).mockRejectedValue(new Error("Unknown collector"));
    render(<Sources />);
    await user.click(await screen.findByLabelText("Collect Windows System log"));
    expect(await screen.findByText("Unknown collector")).toBeInTheDocument();
    expect(screen.getByText("Windows System log")).toBeInTheDocument();
  });

  it("keeps the watch folder under Advanced and explains file import", async () => {
    withCollectors([SYSTEM]);
    vi.mocked(api.getWatcherStatus).mockResolvedValue({ enabled: false });
    render(<Sources />);
    const advanced = (await screen.findByText(/Advanced: watch folder and file import/)).closest("details");
    expect(advanced).not.toHaveAttribute("open");
    expect(within(advanced).getByText(/Import logs/)).toBeInTheDocument();
    expect(await within(advanced).findByText("Live monitoring")).toBeInTheDocument();
  });

  it("explains server mode instead of showing an empty table", async () => {
    withCollectors([], { enabled: false });
    render(<Sources />);
    expect(await screen.findByText(/not available in this mode/)).toBeInTheDocument();
  });
});

describe("First-run gate", () => {
  const at = (path) => render(<MemoryRouter initialEntries={[path]}><App /></MemoryRouter>);

  it("sends a new user to setup, whatever page they asked for", async () => {
    withCollectors([SYSTEM]);
    vi.mocked(api.getSetup).mockResolvedValue({ completed: false, system_logs_enabled: true, platform: "windows" });
    at("/alerts");
    expect(await screen.findByText("Set up system log collection")).toBeInTheDocument();
  });

  it("does not interfere once setup is completed", async () => {
    withCollectors([SYSTEM]);
    vi.mocked(api.getSetup).mockResolvedValue({ completed: true, system_logs_enabled: true, platform: "windows" });
    at("/alerts");
    expect(await screen.findByRole("heading", { name: "Alerts" })).toBeInTheDocument();
  });

  it("does not force setup in server mode", async () => {
    mockApiDefaults();
    vi.mocked(api.getSetup).mockResolvedValue({ completed: false, system_logs_enabled: false, platform: "windows" });
    at("/alerts");
    expect(await screen.findByRole("heading", { name: "Alerts" })).toBeInTheDocument();
  });

  it("never blocks the app when the setup state cannot be read", async () => {
    mockApiDefaults();
    vi.mocked(api.getSetup).mockRejectedValue(new Error("Request failed (500)"));
    at("/alerts");
    expect(await screen.findByRole("heading", { name: "Alerts" })).toBeInTheDocument();
  });

  it("offers Data sources in the navigation", async () => {
    mockApiDefaults();
    at("/");
    expect(await screen.findByRole("link", { name: "Data sources" })).toBeInTheDocument();
  });
});
