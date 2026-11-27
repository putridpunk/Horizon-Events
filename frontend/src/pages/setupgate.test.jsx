import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import SetupGate from "../components/SetupGate.jsx";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import Setup from "./Setup.jsx";

vi.mock("../services/api.js");

function app(path = "/") {
  mockApiDefaults();
  // The server says setup is not finished, and (like a real page) is asked only once while the app is open.
  vi.mocked(api.getSetup).mockResolvedValue({ completed: false, system_logs_enabled: true, platform: "windows" });
  vi.mocked(api.getCollectors).mockResolvedValue({ enabled: true, platform: "windows", items: [
    { id: "windows-system", name: "Windows System log", description: "d", platform: "windows", enabled: false, access: "ready", state: "off", events: 0, last_event: null, error: null }] });
  vi.mocked(api.completeSetup).mockResolvedValue({});
  vi.mocked(api.updateCollector).mockResolvedValue({});
  return render(
    <MemoryRouter initialEntries={[path]}>
      <SetupGate>
        <Routes>
          <Route path="/setup" element={<Setup />} />
          <Route path="*" element={<div>home page</div>} />
        </Routes>
      </SetupGate>
    </MemoryRouter>);
}

describe("first-run setup gate", () => {
  it("sends a first launch to the setup screen", async () => {
    app("/");
    expect(await screen.findByRole("button", { name: "Set up later" })).toBeInTheDocument();
    expect(screen.queryByText("home page")).not.toBeInTheDocument();
  });

  it("lets the user leave the setup screen with 'Set up later' without a restart", async () => {
    app("/");
    await userEvent.click(await screen.findByRole("button", { name: "Set up later" }));
    expect(await screen.findByText("home page")).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 300));  // and the gate must not send them back
    expect(screen.getByText("home page")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Set up later" })).not.toBeInTheDocument();
  });

  it("lets the user leave the setup screen with 'Start collecting' without a restart", async () => {
    app("/setup");
    await userEvent.click(await screen.findByRole("button", { name: "Start collecting" }));
    await waitFor(() => expect(api.updateCollector).toHaveBeenCalled());
    expect(await screen.findByText("home page")).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 300));
    expect(screen.getByText("home page")).toBeInTheDocument();
  });

  it("stays on the setup screen when saving fails, as before", async () => {
    app("/setup");
    vi.mocked(api.completeSetup).mockRejectedValue(new Error("database is locked"));
    await userEvent.click(await screen.findByRole("button", { name: "Set up later" }));
    expect(await screen.findByText("database is locked")).toBeInTheDocument();
    expect(screen.queryByText("home page")).not.toBeInTheDocument();
  });
});
