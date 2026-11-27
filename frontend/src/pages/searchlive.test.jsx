import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import AlertDrawer from "../components/AlertDrawer.jsx";
import IntelCard from "../components/IntelCard.jsx";
import SyslogCard from "../components/SyslogCard.jsx";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import usePolling from "../services/usePolling.js";
import Events from "./Events.jsx";

vi.mock("../services/api.js");

const lastArgs = (fn) => fn.mock.calls.at(-1)[0];

describe("Event search", () => {
  it("sends the typed search to the API as a query", async () => {
    mockApiDefaults();
    render(<Events />);
    await screen.findByText(/No events match/);
    await userEvent.type(screen.getByLabelText("Search events"), "user:admin severity:>=high");
    await waitFor(() => expect(lastArgs(api.listEvents)).toMatchObject({ query: "user:admin severity:>=high", offset: 0 }));
  });

  it("fills the search from a tip", async () => {
    mockApiDefaults();
    render(<Events />);
    await userEvent.click(await screen.findByRole("button", { name: "Use ip:10.0.0.0/8" }));
    expect(screen.getByLabelText("Search events")).toHaveValue("ip:10.0.0.0/8");
  });

  it("shows the server's explanation of a search it cannot understand", async () => {
    mockApiDefaults();
    vi.mocked(api.listEvents).mockRejectedValue(new Error("Unknown field 'colour'. Fields: host, ip."));
    render(<Events />);
    expect(await screen.findByText(/Unknown field 'colour'/)).toBeInTheDocument();
  });

  it("saves the current search under a name, and refuses an empty one", async () => {
    mockApiDefaults();
    vi.mocked(api.createSavedSearch).mockResolvedValue({ id: 1 });
    render(<Events />);
    const save = await screen.findByRole("button", { name: /Save this search/ });
    expect(save).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Search events"), "user:root");
    await userEvent.click(screen.getByRole("button", { name: /Save this search/ }));
    await userEvent.type(screen.getByLabelText("Name for this search"), "Root activity");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.createSavedSearch).toHaveBeenCalledWith("Root activity", "user:root"));
  });

  it("shows why saving failed", async () => {
    mockApiDefaults();
    vi.mocked(api.createSavedSearch).mockRejectedValue(new Error("A saved search with this name already exists."));
    render(<Events />);
    await userEvent.type(await screen.findByLabelText("Search events"), "user:root");
    await userEvent.click(screen.getByRole("button", { name: /Save this search/ }));
    await userEvent.type(screen.getByLabelText("Name for this search"), "Dup");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("already exists");
  });

  it("runs a saved search and can delete it once it is the current search", async () => {
    mockApiDefaults();
    vi.mocked(api.listSavedSearches).mockResolvedValue({ items: [{ id: 7, name: "Root activity", query: "user:root" }], fields: [] });
    vi.mocked(api.deleteSavedSearch).mockResolvedValue({});
    render(<Events />);
    await userEvent.selectOptions(await screen.findByLabelText("Saved searches"), "Root activity");
    expect(screen.getByLabelText("Search events")).toHaveValue("user:root");
    await userEvent.click(await screen.findByRole("button", { name: "Delete saved search Root activity" }));
    await waitFor(() => expect(api.deleteSavedSearch).toHaveBeenCalledWith(7));
  });

  it("links the exports to the current filters", async () => {
    mockApiDefaults();
    render(<Events />);
    expect(await screen.findByRole("link", { name: "Export CSV" })).toHaveAttribute("href", "/api/events/export?format=csv");
    expect(screen.getByRole("link", { name: "Export JSON" })).toHaveAttribute("href", "/api/events/export?format=json");
    await userEvent.type(screen.getByLabelText("Search events"), "x");
    await waitFor(() => expect(lastArgs(api.exportEventsUrl)).toMatchObject({ query: "x" }));
  });
});

// ---- live updates ----------------------------------------------------------------------------------------------
class FakeSource {
  static instances = [];
  constructor(url) {
    this.url = url;
    this.handlers = {};
    this.closed = false;
    FakeSource.instances.push(this);
  }
  addEventListener(type, fn) { this.handlers[type] = fn; }
  close() { this.closed = true; }
  emit(data) { this.handlers.change?.({ data: JSON.stringify(data) }); }
}

function Probe({ load, interval = 60000 }) {
  const { data } = usePolling(load, [], interval);
  return <div>count {data ?? "none"}</div>;
}

describe("Live updates", () => {
  beforeEach(() => { FakeSource.instances = []; vi.stubGlobal("EventSource", FakeSource); });
  afterEach(() => vi.unstubAllGlobals());

  it("refreshes a self-refreshing screen as soon as the server reports a change", async () => {
    let n = 0;
    const load = vi.fn(async () => ++n);
    render(<Probe load={load} />);
    expect(await screen.findByText("count 1")).toBeInTheDocument();
    const [source] = FakeSource.instances;
    expect(source.url).toBe("/api/stream");
    act(() => { source.emit({ changed: ["alerts"] }); source.emit({ changed: ["events"] }); });
    expect(await screen.findByText("count 2")).toBeInTheDocument();  // a burst is one refresh
    expect(load).toHaveBeenCalledTimes(2);
  });

  it("shares one connection between screens and closes it when none is left", async () => {
    const { unmount } = render(<><Probe load={async () => 1} /><Probe load={async () => 2} /></>);
    await screen.findByText("count 1");
    expect(FakeSource.instances).toHaveLength(1);
    unmount();
    expect(FakeSource.instances[0].closed).toBe(true);
  });

  it("does not listen when a screen does not refresh on a timer", async () => {
    render(<Probe load={async () => 1} interval={0} />);
    await screen.findByText("count 1");
    expect(FakeSource.instances).toHaveLength(0);
  });

  it("survives a message it cannot read", async () => {
    let n = 0;
    render(<Probe load={async () => ++n} />);
    await screen.findByText("count 1");
    act(() => FakeSource.instances[0].handlers.change({ data: "not json" }));
    expect(await screen.findByText("count 2")).toBeInTheDocument();
  });
});

// ---- imported lists, matches and syslog --------------------------------------------------------------------------
describe("Imported threat lists", () => {
  it("imports a file under a name and reports what it found", async () => {
    mockApiDefaults();
    vi.mocked(api.getIntelStatus).mockResolvedValue({ feeds: [], min_refresh_minutes: 60 });
    vi.mocked(api.importIntelList).mockResolvedValue({ name: "Team", ips: 2, hashes: 1, domains: 3, skipped: 4, replaced: false });
    render(<IntelCard />);
    const submit = await screen.findByRole("button", { name: "Import list" });
    expect(submit).toBeDisabled();
    await userEvent.type(screen.getByLabelText("List name"), "Team");
    const file = new File(["1.2.3.4\n"], "list.txt", { type: "text/plain" });
    await userEvent.upload(screen.getByLabelText("File"), file);
    await userEvent.click(screen.getByRole("button", { name: "Import list" }));
    await waitFor(() => expect(api.importIntelList).toHaveBeenCalledWith(file, "Team"));
    expect(await screen.findByText('List "Team" saved. Addresses: 2. File hashes: 1. Domains: 3. Lines skipped: 4.')).toBeInTheDocument();
  });

  it("shows why a file was refused", async () => {
    mockApiDefaults();
    vi.mocked(api.getIntelStatus).mockResolvedValue({ feeds: [], min_refresh_minutes: 60 });
    vi.mocked(api.importIntelList).mockRejectedValue(new Error("No IP addresses, file hashes or domain names were found in the file."));
    render(<IntelCard />);
    await userEvent.type(await screen.findByLabelText("List name"), "Bad");
    await userEvent.upload(screen.getByLabelText("File"), new File(["x"], "x.txt"));
    await userEvent.click(screen.getByRole("button", { name: "Import list" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("No IP addresses");
  });

  it("lets only imported lists be removed", async () => {
    mockApiDefaults();
    vi.mocked(api.getIntelStatus).mockResolvedValue({ min_refresh_minutes: 60, feeds: [
      { id: "feodo", name: "abuse.ch Feodo Tracker", source: "network", entries: 5, fetched_at: null, description: "d" },
      { id: "user:team", name: "Team", source: "custom", entries: 3, fetched_at: "2026-11-24T09:00:00", description: "A list you imported from a file." }] });
    vi.mocked(api.deleteIntelList).mockResolvedValue({});
    render(<IntelCard />);
    await screen.findByText("Team");
    expect(screen.queryByRole("button", { name: /Remove list abuse/ })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Remove list Team" }));
    await waitFor(() => expect(api.deleteIntelList).toHaveBeenCalledWith("user:team"));
  });

  it("shows threat-list matches on an alert", async () => {
    mockApiDefaults();
    vi.mocked(api.getAlert).mockResolvedValue({
      id: 5, alert_id: "ALT-000005", rule_id: "HZ-008", rule_name: "Malware detected", severity: "critical", status: "OPEN",
      description: "d", source_ip: null, username: null, occurrences: 1, window_minutes: null, techniques: [],
      created_at: "2026-11-24T09:00:00", last_seen: "2026-11-24T09:00:00", intel: null, events: [], history: [],
      assignee: null, tags: [], age_minutes: 1, sla_minutes: 60, sla_breached: false,
      iocs: [{ kind: "sha256", value: "a".repeat(64), feed: "Known bad" }] });
    render(<MemoryRouter><AlertDrawer alertId={5} onClose={() => {}} /></MemoryRouter>);
    const box = await screen.findByRole("group", { name: "Threat list matches" });
    expect(box).toHaveTextContent("a".repeat(64));
    expect(box).toHaveTextContent("Known bad");
  });
});

describe("Syslog card", () => {
  it("explains how to turn it on when it is off", async () => {
    mockApiDefaults();
    render(<SyslogCard />);
    expect(await screen.findByText(/HORIZON_SYSLOG_PORT/)).toBeInTheDocument();
  });

  it("shows the counters and any error when it is on", async () => {
    mockApiDefaults();
    vi.mocked(api.getSyslogStatus).mockResolvedValue({ enabled: true, bind: "127.0.0.1", port: 5514, received: 12, imported: 10,
      alerts: 2, queued: 0, dropped: 1, last_message: "2026-11-24T09:00:00", last_error: "db down" });
    render(<SyslogCard />);
    expect(await screen.findByText(/Listening on 127\.0\.0\.1:5514/)).toBeInTheDocument();
    expect(screen.getByText("db down")).toBeInTheDocument();
  });
});

describe("Live updates after a refusal", () => {
  beforeEach(() => { FakeSource.instances = []; vi.stubGlobal("EventSource", FakeSource); vi.useFakeTimers({ shouldAdvanceTime: true }); });
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

  it("opens a fresh connection when the browser has given up on the old one", async () => {
    render(<Probe load={async () => 1} />);
    await screen.findByText("count 1");
    const [first] = FakeSource.instances;
    first.readyState = 2;  // closed for good, for example after a 401
    act(() => first.onerror());
    expect(FakeSource.instances).toHaveLength(1);
    await act(async () => { vi.advanceTimersByTime(5000); });
    expect(FakeSource.instances).toHaveLength(2);
  });

  it("does not retry once nobody is listening", async () => {
    const { unmount } = render(<Probe load={async () => 1} />);
    await screen.findByText("count 1");
    const [first] = FakeSource.instances;
    first.readyState = 2;
    act(() => first.onerror());
    unmount();
    await act(async () => { vi.advanceTimersByTime(6000); });
    expect(FakeSource.instances).toHaveLength(1);
  });
});
