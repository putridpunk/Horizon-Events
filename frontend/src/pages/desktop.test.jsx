import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import Settings from "./Settings.jsx";

vi.mock("../services/api.js");

const CFG = { enabled: true, run_in_background: false, notify: "critical", start_with_windows: false };

function page(cfg = CFG) {
  mockApiDefaults();
  vi.mocked(api.getDesktopSettings).mockResolvedValue(cfg);
  vi.mocked(api.updateDesktopSettings).mockResolvedValue(cfg);
  return render(<MemoryRouter><Settings /></MemoryRouter>);
}

describe("Running in the background", () => {
  it("explains the tray and how to quit", async () => {
    page();
    expect(await screen.findByText(/Choose/)).toHaveTextContent("Quit");
    expect(screen.getByLabelText(/Keep running in the system tray/)).not.toBeChecked();
    expect(screen.getByLabelText(/Show a Windows notification/)).toHaveValue("critical");
  });

  it("saves each choice on its own", async () => {
    page();
    await userEvent.click(await screen.findByLabelText(/Keep running in the system tray/));
    await waitFor(() => expect(api.updateDesktopSettings).toHaveBeenCalledWith({ run_in_background: true }));
    await userEvent.selectOptions(screen.getByLabelText(/Show a Windows notification/), "high");
    await waitFor(() => expect(api.updateDesktopSettings).toHaveBeenCalledWith({ notify: "high" }));
    await userEvent.click(screen.getByLabelText(/Start Horizon Events when I sign in/));
    await waitFor(() => expect(api.updateDesktopSettings).toHaveBeenCalledWith({ start_with_windows: true }));
  });

  it("offers notifications to be switched off", async () => {
    page({ ...CFG, notify: "off" });
    expect(await screen.findByLabelText(/Show a Windows notification/)).toHaveValue("off");
  });

  it("shows the server's message when starting with Windows is refused", async () => {
    page();
    vi.mocked(api.updateDesktopSettings).mockRejectedValue(new Error("Starting with Windows works from the installed app, not when running from source."));
    await userEvent.click(await screen.findByLabelText(/Start Horizon Events when I sign in/));
    expect(await screen.findByRole("alert")).toHaveTextContent("installed app");
  });

  it("says it is desktop-only otherwise", async () => {
    page({ enabled: false });
    expect(await screen.findByText(/only available in the desktop app/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/Keep running in the system tray/)).not.toBeInTheDocument();
  });
});
