import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import Settings from "./Settings.jsx";

vi.mock("../services/api.js");

const DEFAULT = String.raw`C:\Users\me\Downloads`;
const CFG = { available: true, enabled: false, folder: "", default_folder: DEFAULT, effective_folder: DEFAULT, watching: false, queued: 0, scanned: 0 };

function page(cfg = CFG) {
  mockApiDefaults();
  vi.mocked(api.getDownloadsScan).mockResolvedValue(cfg);
  vi.mocked(api.updateDownloadsScan).mockResolvedValue(cfg);
  return render(<MemoryRouter><Settings /></MemoryRouter>);
}

afterEach(() => {
  delete window.pywebview;
});

describe("Scan new downloads", () => {
  it("is off by default and shows which folder it would watch", async () => {
    page();
    const box = await screen.findByLabelText(/Scan new files in this folder automatically/);
    expect(box).not.toBeChecked();
    expect(screen.getByText(DEFAULT)).toBeInTheDocument();
    expect(screen.getByText(/Files that are already there are not scanned/)).toBeInTheDocument();
  });

  it("switches on", async () => {
    page();
    await userEvent.click(await screen.findByLabelText(/Scan new files in this folder automatically/));
    await waitFor(() => expect(api.updateDownloadsScan).toHaveBeenCalledWith({ enabled: true }));
  });

  it("reports progress while watching", async () => {
    page({ ...CFG, enabled: true, watching: true, scanned: 4, queued: 2 });
    expect(await screen.findByText("Watching. 4 scanned so far, 2 waiting.")).toBeInTheDocument();
  });

  it("changes the folder through the native picker, and goes back to the default", async () => {
    page({ ...CFG, folder: String.raw`D:\Inbox`, effective_folder: String.raw`D:\Inbox` });
    window.pywebview = { api: { pick_files: vi.fn(), pick_folder: vi.fn().mockResolvedValue([String.raw`E:\Other`]) } };
    await userEvent.click(await screen.findByRole("button", { name: "Choose another folder…" }));
    await waitFor(() => expect(api.updateDownloadsScan).toHaveBeenCalledWith({ folder: String.raw`E:\Other` }));
    await userEvent.click(screen.getByRole("button", { name: "Use the Downloads folder" }));
    await waitFor(() => expect(api.updateDownloadsScan).toHaveBeenCalledWith({ folder: "" }));
  });

  it("explains when the picker is not available", async () => {
    page();
    await userEvent.click(await screen.findByRole("button", { name: "Choose another folder…" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("desktop window");
  });

  it("shows the server's message when the folder is refused", async () => {
    page();
    vi.mocked(api.updateDownloadsScan).mockRejectedValue(new Error("That folder does not exist."));
    await userEvent.click(await screen.findByLabelText(/Scan new files in this folder automatically/));
    expect(await screen.findByText("That folder does not exist.")).toBeInTheDocument();
  });

  it("says it is desktop-only otherwise", async () => {
    page({ ...CFG, available: false });
    expect(await screen.findByText(/Scanning downloads is only available in the desktop app/)).toBeInTheDocument();
  });
});
