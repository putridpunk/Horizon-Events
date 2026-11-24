import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import IntelCard from "./IntelCard.jsx";
import LiveCard from "./LiveCard.jsx";
import ModelCard from "./ModelCard.jsx";

vi.mock("../services/api.js");

const liveStatus = (over = {}) => ({
  enabled: true, running: true, paused: false, directory: "C:/data/watch", interval: 2, total_imported: 12,
  files: [{ path: "linux_auth/auth.log", source_type: "linux_auth", lines: 12, imported: 12, skipped: 0, alerts: 2,
    last_activity: "2026-11-23T14:21:20", last_error: null }], ...over,
});

describe("LiveCard", () => {
  it("explains how to enable live monitoring when it is not configured", async () => {
    mockApiDefaults();
    render(<LiveCard />);
    expect(await screen.findByText(/Set HORIZON_WATCH_DIR/)).toBeInTheDocument();
    expect(screen.getByText("Not configured")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Pause" })).not.toBeInTheDocument();
  });

  it("shows watched files and pauses ingestion", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    vi.mocked(api.getWatcherStatus).mockResolvedValue(liveStatus());
    vi.mocked(api.pauseWatcher).mockResolvedValue({});
    render(<LiveCard />);
    expect(await screen.findByText("linux_auth/auth.log")).toBeInTheDocument();
    expect(screen.getByText("Live")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Pause" }));
    expect(api.pauseWatcher).toHaveBeenCalledTimes(1);
    expect(api.resumeWatcher).not.toHaveBeenCalled();
  });

  it("offers Resume while paused and surfaces a per-file error", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    const status = liveStatus({ paused: true });
    status.files[0].last_error = "RuntimeError: boom";
    vi.mocked(api.getWatcherStatus).mockResolvedValue(status);
    vi.mocked(api.resumeWatcher).mockResolvedValue({});
    render(<LiveCard />);
    expect(await screen.findByText("Paused")).toBeInTheDocument();
    expect(screen.getByText("RuntimeError: boom")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Resume" }));
    expect(api.resumeWatcher).toHaveBeenCalledTimes(1);
  });

  it("hints at the first step when the watch folder has no files yet", async () => {
    mockApiDefaults();
    vi.mocked(api.getWatcherStatus).mockResolvedValue(liveStatus({ files: [] }));
    render(<LiveCard />);
    expect(await screen.findByText(/No files yet/)).toBeInTheDocument();
  });
});

describe("IntelCard", () => {
  const feeds = [
    { id: "demo", name: "Synthetic demo feed (not real intelligence)", source: "demo", entries: 3, fetched_at: null, description: "Synthetic data." },
    { id: "feodo", name: "abuse.ch Feodo Tracker", source: "network", entries: 5, fetched_at: "2026-11-23T16:15:10", description: "Botnet C2 IPs." },
  ];

  it("lists feeds and states what a refresh contacts and sends", async () => {
    mockApiDefaults();
    vi.mocked(api.getIntelStatus).mockResolvedValue({ feeds, min_refresh_minutes: 60 });
    render(<IntelCard />);
    expect(await screen.findByText("abuse.ch Feodo Tracker")).toBeInTheDocument();
    expect(screen.getByText("bundled")).toBeInTheDocument();
    expect(screen.getByText(/no log data is sent/)).toBeInTheDocument();
  });

  it("shows the per-feed result of a refresh, including 'too_soon' and errors", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    vi.mocked(api.getIntelStatus).mockResolvedValue({ feeds, min_refresh_minutes: 60 });
    vi.mocked(api.refreshIntel).mockResolvedValue({ results: [
      { feed: "feodo", status: "too_soon", entries: 5, message: "Refreshed less than an hour ago; try again later." },
      { feed: "spamhaus_drop", status: "error", entries: 0, message: "OSError: network down" },
    ], feeds });
    render(<IntelCard />);
    await user.click(await screen.findByRole("button", { name: "Refresh feeds" }));
    expect(await screen.findByText(/feodo: too_soon/)).toBeInTheDocument();
    const failed = screen.getByText(/spamhaus_drop: error/);
    expect(failed).toHaveClass("error");
    expect(failed).toHaveTextContent("network down");
  });

  it("shows the request error when the refresh call itself fails", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    vi.mocked(api.refreshIntel).mockRejectedValue(new Error("Request failed (502)"));
    render(<IntelCard />);
    await user.click(await screen.findByRole("button", { name: "Refresh feeds" }));
    expect(await screen.findByText("Request failed (502)")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh feeds" })).toBeEnabled();
  });
});

describe("ModelCard", () => {
  it("says anomaly detection is inactive until a model is trained", async () => {
    mockApiDefaults();
    render(<ModelCard />);
    expect(await screen.findByText(/No model trained yet/, undefined, { timeout: 4000 })).toBeInTheDocument();
  });

  it("trains on the synthetic baseline and refreshes the status", async () => {
    const user = userEvent.setup();
    const onTrained = vi.fn();
    mockApiDefaults();
    vi.mocked(api.trainModel).mockResolvedValue({});
    vi.mocked(api.getModelStatus)
      .mockResolvedValueOnce({ trained: false, trained_at: null, windows: 0, source: null, features: ["events"] })
      .mockResolvedValue({ trained: true, trained_at: "2026-11-23T16:00:00", windows: 3209, source: "synthetic", features: ["events"] });
    render(<ModelCard onTrained={onTrained} />);
    await user.click(await screen.findByRole("button", { name: "Train on synthetic baseline" }));
    expect(api.trainModel).toHaveBeenCalledWith("synthetic");
    expect(await screen.findByText(/3209 per-IP hourly windows \(synthetic\)/)).toBeInTheDocument();
    expect(onTrained).toHaveBeenCalled();
  });

  it("shows the server's explanation when your own data is too thin", async () => {
    const user = userEvent.setup();
    mockApiDefaults();
    vi.mocked(api.trainModel).mockRejectedValue(new Error("Need at least 50 per-IP hourly windows to train, found 4. Try training on the synthetic baseline instead."));
    render(<ModelCard />);
    await user.click(await screen.findByRole("button", { name: "Train on my data" }));
    expect(api.trainModel).toHaveBeenCalledWith("database");
    await waitFor(() => expect(screen.getByText(/found 4/)).toBeInTheDocument());
  });
});
