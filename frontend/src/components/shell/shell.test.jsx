import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { collector } from "../../test/fixtures.js";
import { mockApiDefaults } from "../../test/mockApi.js";
import * as api from "../../services/api.js";
import { routerFuture } from "../../routerFuture.js";
import { getTheme, initTheme } from "../../theme/theme.js";
import Layout from "../Layout.jsx";

vi.mock("../../services/api.js");

const at = (path) => render(
  <MemoryRouter initialEntries={[path]} future={routerFuture}>
    <Layout><p>page body</p></Layout>
  </MemoryRouter>);

beforeEach(() => {
  localStorage.clear();
  initTheme();
  mockApiDefaults();
});

describe("sidebar", () => {
  it("groups the pages under Monitor, Respond and Insight", () => {
    at("/");
    const nav = within(screen.getByRole("navigation", { name: "Main" }));
    const groups = Object.fromEntries(["Monitor", "Respond", "Insight"].map((name) => [
      name, within(nav.getByText(name).closest(".nav-group")).getAllByRole("link").map((a) => a.textContent)]));
    expect(groups).toEqual({
      Monitor: ["Overview", "Events", "Data sources"],
      Respond: ["Alerts", "Incidents", "Scan files"],
      Insight: ["Analytics", "Reports"],
    });
  });

  it("marks the current page for everyone, including screen readers", () => {
    at("/alerts");
    const current = screen.getByRole("link", { name: "Alerts" });
    expect(current).toHaveClass("active");
    expect(current).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Overview" })).not.toHaveAttribute("aria-current");
  });

  it("uses a plain, sentence-case wordmark", () => {
    at("/");
    expect(screen.getByText("Horizon Events", { selector: ".brand div" })).toBeInTheDocument();
  });
});

describe("top bar", () => {
  it.each([["/", "Monitor", "Overview"], ["/sources", "Monitor", "Data sources"], ["/incidents", "Respond", "Incidents"],
    ["/reports", "Insight", "Reports"]])("on %s the breadcrumb reads %s / %s", (path, group, title) => {
    at(path);
    const bar = screen.getByRole("banner");
    expect(within(bar).getByText(group)).toBeInTheDocument();
    expect(within(bar).getByText(title)).toBeInTheDocument();
  });

  it("falls back gracefully on an unknown page", () => {
    at("/nowhere");
    expect(within(screen.getByRole("banner")).getByText("Horizon Events")).toBeInTheDocument();
  });

  it.each(["/", "/events", "/alerts", "/incidents", "/sources", "/analytics", "/reports"])(
    "offers Import logs from %s", (path) => {
      at(path);
      expect(screen.getByRole("button", { name: /Import logs/ })).toBeInTheDocument();
    });

  it("switches theme from the bar", async () => {
    const user = userEvent.setup();
    at("/");
    await user.click(screen.getByRole("button", { name: "Switch to dark theme" }));
    expect(getTheme()).toBe("dark");
    expect(screen.getByRole("button", { name: "Switch to light theme" })).toBeInTheDocument();
  });
});

describe("collection indicator", () => {
  const indicator = () => screen.getByTestId("live-indicator");

  it("says Collecting when a system log source is collecting", async () => {
    vi.mocked(api.getCollectors).mockResolvedValue({ enabled: true, platform: "windows",
      items: [collector({ state: "collecting", enabled: true })] });
    at("/");
    await waitFor(() => expect(indicator()).toHaveTextContent("Collecting"));
    expect(indicator()).toHaveClass("on");
  });

  it("counts a running watch folder too", async () => {
    vi.mocked(api.getWatcherStatus).mockResolvedValue({ enabled: true, running: true, paused: false, files: [] });
    at("/");
    await waitFor(() => expect(indicator()).toHaveTextContent("Collecting"));
  });

  it("says Not collecting when nothing is on, a paused watcher, or the API fails", async () => {
    vi.mocked(api.getWatcherStatus).mockResolvedValue({ enabled: true, running: true, paused: true, files: [] });
    at("/");
    await new Promise((r) => setTimeout(r, 80));
    expect(indicator()).toHaveTextContent("Not collecting");
    expect(indicator()).not.toHaveClass("on");
  });

  it("does not crash when both status calls fail", async () => {
    vi.mocked(api.getCollectors).mockRejectedValue(new Error("down"));
    vi.mocked(api.getWatcherStatus).mockRejectedValue(new Error("down"));
    at("/");
    await new Promise((r) => setTimeout(r, 80));
    expect(indicator()).toHaveTextContent("Not collecting");
  });

  it("explains itself on hover", () => {
    at("/");
    expect(indicator()).toHaveAttribute("title", expect.stringMatching(/system logs|watch folder/i));
  });
});

describe("keyboard access", () => {
  it("lets keyboard users skip the navigation", async () => {
    const user = userEvent.setup();
    at("/");
    await user.tab();
    const skip = screen.getByRole("link", { name: "Skip to content" });
    expect(skip).toHaveFocus();
    expect(skip).toHaveAttribute("href", "#content");
    expect(document.getElementById("content")).toContainElement(screen.getByText("page body"));
  });
});
