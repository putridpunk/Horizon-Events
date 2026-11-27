import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AuthGate from "../auth/AuthGate.jsx";
import AccountCard from "../components/settings/AccountCard.jsx";
import UpdateCard from "../components/settings/UpdateCard.jsx";
import UsersCard from "../components/settings/UsersCard.jsx";
import TopBar from "../components/shell/TopBar.jsx";
import { DEFAULT_PREFS, STORAGE_KEY, loadPrefs, rangeBucket, rangeStart, sanitize, savePrefs } from "../lib/dashboardPrefs.js";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import Overview from "./Overview.jsx";

vi.mock("../services/api.js");
// Chart.js needs a real canvas; the charts themselves are not under test here.
vi.mock("../charts/charts.jsx", () => ({
  EventsOverTime: () => <div>chart:events-over-time</div>,
  SeverityDoughnut: () => <div>chart:severity</div>,
  HorizontalBars: () => <div>chart:bars</div>,
}));

const ADMIN = { enabled: true, setup_required: false, user: { username: "boss", role: "admin" } };

function gate(status, children = <div>the app</div>) {
  mockApiDefaults();
  vi.mocked(api.getAuthStatus).mockResolvedValue(status);
  return render(<MemoryRouter><AuthGate>{children}</AuthGate></MemoryRouter>);
}

describe("Sign-in gate", () => {
  it("shows the app straight away when sign-in is off", async () => {
    gate({ enabled: false, setup_required: false, user: null });
    expect(await screen.findByText("the app")).toBeInTheDocument();
  });

  it("asks for credentials when sign-in is on, and shows the server's refusal", async () => {
    gate({ enabled: true, setup_required: false, user: null });
    vi.mocked(api.login).mockRejectedValueOnce(new Error("Wrong user name or password."));
    expect(screen.queryByText("the app")).not.toBeInTheDocument();
    await userEvent.type(await screen.findByLabelText("User name"), "alice");
    expect(screen.getByRole("button", { name: "Sign in" })).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Password"), "bad password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Wrong user name or password.");
    expect(screen.queryByText("the app")).not.toBeInTheDocument();
  });

  it("lets the app in after a successful sign-in", async () => {
    gate({ enabled: true, setup_required: false, user: null });
    vi.mocked(api.login).mockResolvedValue({});
    vi.mocked(api.getAuthStatus).mockResolvedValue(ADMIN);  // what the page asks after signing in
    await userEvent.type(await screen.findByLabelText("User name"), "boss");
    await userEvent.type(screen.getByLabelText("Password"), "a long enough one");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("the app")).toBeInTheDocument();
    expect(api.login).toHaveBeenCalledWith("boss", "a long enough one");
  });

  it("creates the first administrator with the setup code", async () => {
    gate({ enabled: true, setup_required: true, user: null });
    vi.mocked(api.setupAdmin).mockResolvedValue({});
    await userEvent.type(await screen.findByLabelText("Setup code"), "abc123");
    await userEvent.type(screen.getByLabelText("User name"), "boss");
    await userEvent.type(screen.getByLabelText("Password"), "twelve chars plus");
    await userEvent.click(screen.getByRole("button", { name: "Create administrator" }));
    await waitFor(() => expect(api.setupAdmin).toHaveBeenCalledWith("abc123", "boss", "twelve chars plus"));
  });

  it("returns to the sign-in page when a request says the session ended", async () => {
    gate(ADMIN);
    expect(await screen.findByText("the app")).toBeInTheDocument();
    vi.mocked(api.getAuthStatus).mockResolvedValue({ enabled: true, setup_required: false, user: null });
    act(() => { window.dispatchEvent(new Event("horizon-auth-required")); });
    expect(await screen.findByRole("form", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByText("the app")).not.toBeInTheDocument();
  });

  it("says so when the server cannot be reached", async () => {
    mockApiDefaults();
    vi.mocked(api.getAuthStatus).mockRejectedValue(new Error("Request failed (502)"));
    render(<MemoryRouter><AuthGate><div>the app</div></AuthGate></MemoryRouter>);
    expect(await screen.findByRole("alert")).toHaveTextContent("Request failed (502)");
  });

  it("shows who is signed in on the top bar, with a way out", async () => {
    gate(ADMIN, <TopBar />);
    vi.mocked(api.logout).mockResolvedValue({});
    expect(await screen.findByText(/boss \(admin\)/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(api.logout).toHaveBeenCalled());
  });
});

describe("People and account", () => {
  const USERS = { roles: ["viewer", "analyst", "admin"], items: [
    { id: 1, username: "boss", role: "admin", disabled: false, locked: false, last_login: "2026-11-24T09:00:00" },
    { id: 2, username: "vera", role: "viewer", disabled: false, locked: true, last_login: null }] };

  it("is hidden from everyone but administrators, and when sign-in is off", async () => {
    gate({ enabled: true, setup_required: false, user: { username: "vera", role: "viewer" } }, <><UsersCard /><p>after</p></>);
    expect(await screen.findByText("after")).toBeInTheDocument();
    expect(screen.queryByText("People")).not.toBeInTheDocument();
  });

  it("lists people, and cannot disable or delete yourself", async () => {
    gate(ADMIN, <UsersCard />);
    vi.mocked(api.listUsers).mockResolvedValue(USERS);
    expect(await screen.findByText("vera")).toBeInTheDocument();
    expect(screen.getByText(/\(locked\)/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete boss" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Disable boss" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Delete vera" })).toBeEnabled();
  });

  it("changes a role, unlocks, disables and deletes", async () => {
    gate(ADMIN, <UsersCard />);
    vi.mocked(api.listUsers).mockResolvedValue(USERS);
    vi.mocked(api.updateUser).mockResolvedValue({});
    vi.mocked(api.deleteUser).mockResolvedValue({});
    await userEvent.selectOptions(await screen.findByLabelText("Role of vera"), "analyst");
    await waitFor(() => expect(api.updateUser).toHaveBeenCalledWith(2, { role: "analyst" }));
    await userEvent.click(screen.getByRole("button", { name: "Unlock vera" }));
    await waitFor(() => expect(api.updateUser).toHaveBeenCalledWith(2, { unlock: true }));
    await userEvent.click(screen.getByRole("button", { name: "Disable vera" }));
    await waitFor(() => expect(api.updateUser).toHaveBeenCalledWith(2, { disabled: true }));
    await userEvent.click(screen.getByRole("button", { name: "Delete vera" }));
    await waitFor(() => expect(api.deleteUser).toHaveBeenCalledWith(2));
  });

  it("resets a password and adds a person, showing the server's reasons", async () => {
    gate(ADMIN, <UsersCard />);
    vi.mocked(api.listUsers).mockResolvedValue(USERS);
    vi.mocked(api.updateUser).mockResolvedValue({});
    vi.mocked(api.createUser).mockRejectedValueOnce(new Error("Use a password of at least 12 characters.")).mockResolvedValue({});
    await userEvent.click(await screen.findByRole("button", { name: "Reset password of vera" }));
    await userEvent.type(screen.getByLabelText(/^New password for vera \(at least/), "a new passphrase!");
    await userEvent.click(screen.getByRole("button", { name: "Set password" }));
    await waitFor(() => expect(api.updateUser).toHaveBeenCalledWith(2, { password: "a new passphrase!" }));
    const form = screen.getByRole("form", { name: "Add a person" });
    await userEvent.type(within(form).getByLabelText("User name"), "newbie");
    await userEvent.type(within(form).getByLabelText(/^Password/), "short");
    await userEvent.click(within(form).getByRole("button", { name: "Add person" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("at least 12 characters");
    await userEvent.click(within(form).getByRole("button", { name: "Add person" }));
    await waitFor(() => expect(api.createUser).toHaveBeenLastCalledWith({ username: "newbie", password: "short", role: "viewer" }));
  });

  it("changes your own password", async () => {
    gate(ADMIN, <AccountCard />);
    vi.mocked(api.changePassword).mockResolvedValue({});
    await userEvent.type(await screen.findByLabelText("Current password"), "old one here");
    await userEvent.type(screen.getByLabelText(/New password/), "new one here ok");
    await userEvent.click(screen.getByRole("button", { name: "Change password" }));
    await waitFor(() => expect(api.changePassword).toHaveBeenCalledWith("old one here", "new one here ok"));
    expect(await screen.findByText(/other sign-ins have been ended/)).toBeInTheDocument();
  });

  it("shows nothing about accounts when sign-in is off", async () => {
    gate({ enabled: false, setup_required: false, user: null }, <><AccountCard /><p>after</p></>);
    expect(await screen.findByText("after")).toBeInTheDocument();
    expect(screen.queryByText("Your account")).not.toBeInTheDocument();
  });
});

describe("Updates", () => {
  const STATUS = { current: "1.5.0", auto_check: false, checked_at: null, latest: null, update_available: false, url: null, notes: null, error: null };

  it("offers a check, and says when you are up to date", async () => {
    mockApiDefaults();
    vi.mocked(api.getUpdateStatus).mockResolvedValue(STATUS);
    vi.mocked(api.checkForUpdate).mockResolvedValue({ ...STATUS, checked_at: "2026-11-27T10:00:00", latest: "1.5.0" });
    render(<UpdateCard />);
    await userEvent.click(await screen.findByRole("button", { name: "Check for updates now" }));
    expect(await screen.findByText(/This is the latest version/)).toBeInTheDocument();
  });

  it("shows a newer version with a link to its page, and installs nothing", async () => {
    mockApiDefaults();
    vi.mocked(api.getUpdateStatus).mockResolvedValue({ ...STATUS, update_available: true, latest: "1.6.0", notes: "Adds things.",
      url: "https://github.com/putridpunk/Horizon-Events/releases/tag/v1.6.0", checked_at: "2026-11-27T10:00:00" });
    render(<UpdateCard />);
    const box = await screen.findByRole("group", { name: "Update available" });
    expect(box).toHaveTextContent("Version 1.6.0 is available.");
    const link = within(box).getByRole("link", { name: /See what changed/ });
    expect(link).toHaveAttribute("href", "https://github.com/putridpunk/Horizon-Events/releases/tag/v1.6.0");
    expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
  });

  it("turns automatic checks on, and explains a failure", async () => {
    mockApiDefaults();
    vi.mocked(api.getUpdateStatus).mockResolvedValue({ ...STATUS, error: "Could not reach GitHub. Check the internet connection." });
    vi.mocked(api.setAutoUpdateCheck).mockResolvedValue({ ...STATUS, auto_check: true });
    render(<UpdateCard />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not reach GitHub");
    await userEvent.click(screen.getByRole("checkbox", { name: /automatically once a day/ }));
    await waitFor(() => expect(api.setAutoUpdateCheck).toHaveBeenCalledWith(true));
  });

  it("badges the top bar only when there is a newer version", async () => {
    mockApiDefaults();
    vi.mocked(api.getUpdateStatus).mockResolvedValue({ ...STATUS, update_available: true, latest: "1.6.0" });
    render(<MemoryRouter><TopBar /></MemoryRouter>);
    expect(await screen.findByRole("link", { name: "Update available" })).toHaveAttribute("href", "/settings");
  });
});

// ---- dashboard preferences -------------------------------------------------------------------------------------
describe("Dashboard preferences", () => {
  const memory = () => {
    const data = {};
    return { getItem: (k) => data[k] ?? null, setItem: (k, v) => { data[k] = v; }, data };
  };

  it("cleans up anything stored: unknown widgets, duplicates, bad ranges, damaged text", () => {
    expect(sanitize({ order: ["ips", "nope", "ips"], hidden: ["x", "types"], range: "7d" }))
      .toEqual({ order: ["ips", "stats", "attention", "timeline", "types", "severity"], hidden: ["types"], range: "7d" });
    expect(sanitize({ range: "forever" }).range).toBe("all");
    expect(sanitize("junk")).toEqual(DEFAULT_PREFS);
    const bad = memory();
    bad.setItem(STORAGE_KEY, "{not json");
    expect(loadPrefs(bad)).toEqual(DEFAULT_PREFS);
  });

  it("saves and loads", () => {
    const store = memory();
    savePrefs({ order: ["timeline", "stats"], hidden: ["attention"], range: "24h" }, store);
    expect(loadPrefs(store)).toMatchObject({ hidden: ["attention"], range: "24h" });
    expect(loadPrefs(store).order.slice(0, 2)).toEqual(["timeline", "stats"]);
  });

  it("turns a range into a start time and a bucket", () => {
    expect(rangeStart("all")).toBeUndefined();
    expect(rangeStart("24h", Date.parse("2026-11-27T10:00:00Z"))).toBe("2026-11-26T10:00:00");
    expect([rangeBucket("24h"), rangeBucket("7d"), rangeBucket("30d"), rangeBucket("all")]).toEqual(["hour", "hour", "day", "hour"]);
  });
});

describe("Overview customization", () => {
  beforeEach(() => localStorage.clear());

  it("starts with the standard layout", async () => {
    mockApiDefaults();
    render(<MemoryRouter><Overview /></MemoryRouter>);
    expect(await screen.findByText("Events collected")).toBeInTheDocument();
    expect(screen.getByText("Needs attention")).toBeInTheDocument();
    expect(screen.queryByText("Most common source IPs")).not.toBeInTheDocument();
    expect(api.getSourceIps).not.toHaveBeenCalled();  // hidden widgets cost no requests
  });

  it("hides and shows widgets, remembers the choice, and fetches only what is shown", async () => {
    mockApiDefaults();
    vi.mocked(api.getSourceIps).mockResolvedValue([{ name: "203.0.113.7", count: 4 }]);
    const { unmount } = render(<MemoryRouter><Overview /></MemoryRouter>);
    await userEvent.click(await screen.findByRole("button", { name: "Customize" }));
    await userEvent.click(screen.getByRole("checkbox", { name: "Most common source IPs" }));
    await userEvent.click(screen.getByRole("checkbox", { name: "Events over time" }));
    await waitFor(() => expect(api.getSourceIps).toHaveBeenCalled());
    expect(JSON.parse(localStorage.getItem(STORAGE_KEY)).hidden).toEqual(expect.arrayContaining(["timeline", "types", "severity"]));
    unmount();
    mockApiDefaults();
    render(<MemoryRouter><Overview /></MemoryRouter>);
    await screen.findByText("Events collected");
    expect(screen.getByText("Most common source IPs")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Events over time" })).not.toBeInTheDocument();
  });

  it("reorders widgets", async () => {
    mockApiDefaults();
    render(<MemoryRouter><Overview /></MemoryRouter>);
    await userEvent.click(await screen.findByRole("button", { name: "Customize" }));
    await userEvent.click(screen.getByRole("button", { name: "Move Events over time up" }));
    expect(JSON.parse(localStorage.getItem(STORAGE_KEY)).order.slice(0, 3)).toEqual(["stats", "timeline", "attention"]);
    expect(screen.getByRole("button", { name: "Move Key numbers up" })).toBeDisabled();
  });

  it("asks for the chosen time range, and the standard layout comes back with one click", async () => {
    mockApiDefaults();
    render(<MemoryRouter><Overview /></MemoryRouter>);
    await userEvent.click(await screen.findByRole("button", { name: "Customize" }));
    await userEvent.selectOptions(screen.getByLabelText("Time range of the chart"), "24h");
    await waitFor(() => expect(vi.mocked(api.getTimeseries).mock.calls.at(-1)[0]).toMatchObject({ bucket: "hour", start: expect.any(String) }));
    await userEvent.click(screen.getByRole("button", { name: "Back to the standard layout" }));
    await waitFor(() => expect(vi.mocked(api.getTimeseries).mock.calls.at(-1)[0]).toEqual({ bucket: "hour" }));
  });

  it("says so when everything is hidden", async () => {
    mockApiDefaults();
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ hidden: ["stats", "attention", "timeline", "types", "ips", "severity"] }));
    render(<MemoryRouter><Overview /></MemoryRouter>);
    expect(await screen.findByText(/Everything is hidden/)).toBeInTheDocument();
  });
});
