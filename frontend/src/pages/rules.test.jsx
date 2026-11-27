import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import GeoIpCard from "../components/settings/GeoIpCard.jsx";
import { fromRule, toParams } from "../components/rules/RuleEditor.jsx";
import { mockApiDefaults } from "../test/mockApi.js";
import * as api from "../services/api.js";
import Rules from "./Rules.jsx";
import AlertDrawer from "../components/AlertDrawer.jsx";

vi.mock("../services/api.js");

const BUILTIN = { id: "HZ-001", name: "Repeated login failures", description: "Many failed logins", severity: "high", enabled: true,
  custom: false, params: { threshold: 5, window_minutes: 5 }, techniques: [] };
const MINE = { id: "CR-001", name: "Root from outside", description: "Root logons", severity: "high", enabled: true, custom: true,
  params: { when: { all: [{ field: "username", op: "eq", value: "root" }, { field: "source_ip", op: "present" }] },
    threshold: 3, window_minutes: 15, group_by: "source_ip" }, techniques: [] };
const NESTED = { ...MINE, id: "CR-002", name: "Imported", params: { when: { all: [{ field: "raw", op: "raw_field", name: "EventID", value: "4625" }] },
  threshold: 1, window_minutes: 10, group_by: "none" } };
const REPLAY = { rule_id: "CR-000", days: 7, events_scanned: 120, truncated: false, would_alert: 2, already_alerted: 1,
  by_severity: { critical: 0, high: 2, medium: 0, low: 0 }, top_sources: [{ value: "203.0.113.7", count: 2 }], shown: 2,
  note: "Replay treats the whole period as one batch.", detections: [
    { key: "a", severity: "high", description: "Many failures", source_ip: "203.0.113.7", username: "admin", occurrences: 12,
      first_event: "2026-11-20T10:00:00", last_event: "2026-11-20T10:05:00", event_ids: [1], already_alerted: true },
    { key: "b", severity: "high", description: "Other", source_ip: null, username: null, occurrences: 5, first_event: null,
      last_event: null, event_ids: [], already_alerted: false }] };

function page(rules = [BUILTIN, MINE]) {
  mockApiDefaults();
  vi.mocked(api.listRules).mockResolvedValue(rules);
  return render(<MemoryRouter><Rules /></MemoryRouter>);
}

describe("editor conversion", () => {
  it("round-trips a flat rule and keeps a complex one as it was", () => {
    const f = fromRule(MINE);
    expect(f.match).toBe("all");
    expect(f.conditions).toHaveLength(2);
    expect(toParams(f)).toEqual({ when: MINE.params.when, threshold: 3, window_minutes: 15, group_by: "source_ip" });
    const nested = fromRule(NESTED);
    expect(nested.nested).toEqual(NESTED.params.when);
    expect(toParams(nested).when).toEqual(NESTED.params.when);
  });
});

describe("Rules page", () => {
  it("lists your rules apart from the built-in ones and switches a rule off", async () => {
    page();
    expect(await screen.findByText("Root from outside")).toBeInTheDocument();
    expect(screen.getByText("Repeated login failures")).toBeInTheDocument();
    vi.mocked(api.updateRule).mockResolvedValue({});
    await userEvent.click(screen.getByRole("checkbox", { name: "Repeated login failures enabled" }));
    await waitFor(() => expect(api.updateRule).toHaveBeenCalledWith("HZ-001", { enabled: false }));
  });

  it("offers no tuning for malware detections, which come from scans", async () => {
    page([{ ...BUILTIN, id: "HZ-008", name: "Malware detected" }]);
    await screen.findByText("Malware detected");
    expect(screen.queryByRole("button", { name: /Tune Malware/ })).not.toBeInTheDocument();
  });

  it("creates a rule from the builder, after testing it on the past", async () => {
    page([]);
    vi.mocked(api.replayRule).mockResolvedValue(REPLAY);
    vi.mocked(api.createCustomRule).mockResolvedValue({});
    await userEvent.click(await screen.findByRole("button", { name: "New rule…" }));
    await userEvent.type(screen.getByLabelText("Name"), "Admin spray");
    await userEvent.clear(screen.getByLabelText("Condition 1 value"));
    await userEvent.type(screen.getByLabelText("Condition 1 value"), "unknown_user");
    await userEvent.clear(screen.getByLabelText(/^after at least/));
    await userEvent.type(screen.getByLabelText(/^after at least/), "4");
    await userEvent.selectOptions(screen.getByLabelText("Count separately for each"), "source_ip");
    await userEvent.click(screen.getByRole("button", { name: "Test this rule" }));
    const result = await screen.findByRole("region", { name: "Test result" });
    expect(result).toHaveTextContent("2 alerts would have been raised from 120 events in the last 7 days (1 already has an alert)");
    expect(within(result).getByText(/already alerted/)).toBeInTheDocument();
    expect(api.replayRule).toHaveBeenCalledWith({ name: "Admin spray", severity: "medium", days: 7, params: {
      when: { all: [{ field: "event_type", op: "eq", value: "unknown_user" }] }, threshold: 4, window_minutes: 10, group_by: "source_ip" } });
    expect(api.createCustomRule).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Create rule" }));
    await waitFor(() => expect(api.createCustomRule).toHaveBeenCalledWith(expect.objectContaining({ name: "Admin spray", enabled: true })));
  });

  it("adds and removes conditions, and hides the value for tests that need none", async () => {
    page([]);
    await userEvent.click(await screen.findByRole("button", { name: "New rule…" }));
    expect(screen.getByRole("button", { name: "Remove condition 1" })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Add a condition" }));
    await userEvent.selectOptions(screen.getByLabelText("Condition 2 test"), "present");
    expect(screen.queryByLabelText("Condition 2 value")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Remove condition 2" }));
    expect(screen.queryByRole("group", { name: "Condition 2" })).not.toBeInTheDocument();
  });

  it("shows the server's reason when a rule is refused", async () => {
    page([]);
    vi.mocked(api.createCustomRule).mockRejectedValue(new Error("Unknown field 'colour'."));
    await userEvent.click(await screen.findByRole("button", { name: "New rule…" }));
    await userEvent.type(screen.getByLabelText("Name"), "x");
    await userEvent.click(screen.getByRole("button", { name: "Create rule" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Unknown field 'colour'.");
  });

  it("edits one of your rules with its current values", async () => {
    page();
    vi.mocked(api.replaceCustomRule).mockResolvedValue({});
    await userEvent.click(await screen.findByRole("button", { name: "Edit Root from outside" }));
    expect(screen.getByLabelText("Name")).toHaveValue("Root from outside");
    expect(screen.getByLabelText("Condition 1 value")).toHaveValue("root");
    expect(screen.getByLabelText(/^after at least/)).toHaveValue(3);
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(api.replaceCustomRule).toHaveBeenCalledWith("CR-001", expect.objectContaining({ params: MINE.params })));
  });

  it("keeps imported conditions it cannot show, and says so", async () => {
    page([NESTED]);
    vi.mocked(api.replaceCustomRule).mockResolvedValue({});
    await userEvent.click(await screen.findByRole("button", { name: "Edit Imported" }));
    expect(screen.getByText(/more complex than this editor shows/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(api.replaceCustomRule.mock.calls[0][1].params.when).toEqual(NESTED.params.when));
  });

  it("deletes one of your rules", async () => {
    page();
    vi.mocked(api.deleteCustomRule).mockResolvedValue({});
    await userEvent.click(await screen.findByRole("button", { name: "Delete Root from outside" }));
    await waitFor(() => expect(api.deleteCustomRule).toHaveBeenCalledWith("CR-001"));
  });
});

describe("Tuning a built-in rule", () => {
  it("tests new settings before saving them", async () => {
    page();
    vi.mocked(api.replayRule).mockResolvedValue(REPLAY);
    vi.mocked(api.updateRule).mockResolvedValue({});
    await userEvent.click(await screen.findByRole("button", { name: "Tune Repeated login failures" }));
    const box = screen.getByLabelText("Settings (JSON)");
    await userEvent.clear(box);
    await userEvent.click(box);
    await userEvent.paste('{"threshold": 20}');
    await userEvent.click(screen.getByRole("button", { name: "Test these settings" }));
    await screen.findByRole("region", { name: "Test result" });
    expect(api.replayRule).toHaveBeenCalledWith({ rule_id: "HZ-001", severity: "high", params: { threshold: 20 }, days: 7 });
    expect(api.updateRule).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.updateRule).toHaveBeenCalledWith("HZ-001", { severity: "high", params: { threshold: 20 } }));
  });

  it("explains broken settings instead of sending them", async () => {
    page();
    await userEvent.click(await screen.findByRole("button", { name: "Tune Repeated login failures" }));
    const box = screen.getByLabelText("Settings (JSON)");
    await userEvent.clear(box);
    await userEvent.click(box);
    await userEvent.paste("not json");
    await userEvent.click(screen.getByRole("button", { name: "Test these settings" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("must be a JSON object");
    expect(api.replayRule).not.toHaveBeenCalled();
  });
});

describe("Sigma import", () => {
  it("checks the rule before importing it", async () => {
    page([]);
    vi.mocked(api.importSigmaRule).mockResolvedValue({ saved: false, name: "Admin logons", severity: "high", description: "From outside" });
    await userEvent.click(await screen.findByRole("button", { name: "Import a Sigma rule…" }));
    expect(screen.getByRole("button", { name: "Import rule" })).toBeDisabled();
    await userEvent.click(screen.getByLabelText("Sigma rule (YAML)"));
    await userEvent.paste("title: Admin logons");
    await userEvent.click(screen.getByRole("button", { name: "Check the rule" }));
    const preview = await screen.findByRole("group", { name: "Rule preview" });
    expect(preview).toHaveTextContent("Admin logons");
    expect(api.importSigmaRule).toHaveBeenCalledWith("title: Admin logons", false);
    await userEvent.click(screen.getByRole("button", { name: "Import rule" }));
    await waitFor(() => expect(api.importSigmaRule).toHaveBeenLastCalledWith("title: Admin logons", true));
  });

  it("shows why a rule is not supported", async () => {
    page([]);
    vi.mocked(api.importSigmaRule).mockRejectedValue(new Error("The modifier '|re' is not supported."));
    await userEvent.click(await screen.findByRole("button", { name: "Import a Sigma rule…" }));
    await userEvent.click(screen.getByLabelText("Sigma rule (YAML)"));
    await userEvent.paste("x");
    await userEvent.click(screen.getByRole("button", { name: "Check the rule" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("not supported");
    expect(screen.queryByRole("group", { name: "Rule preview" })).not.toBeInTheDocument();
  });
});

describe("Locations", () => {
  it("sets the database path and can stop using it", async () => {
    mockApiDefaults();
    vi.mocked(api.getGeoIp).mockResolvedValue({ configured: true, path: "C:\\geo\\City.mmdb", database: { type: "GeoLite2-City" }, error: null });
    vi.mocked(api.setGeoIp).mockResolvedValue({});
    render(<GeoIpCard />);
    expect(await screen.findByText("C:\\geo\\City.mmdb")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText(/Full path/), "  C:\\geo\\New.mmdb ");
    await userEvent.click(screen.getByRole("button", { name: "Use this database" }));
    await waitFor(() => expect(api.setGeoIp).toHaveBeenCalledWith("C:\\geo\\New.mmdb"));
    await userEvent.click(screen.getByRole("button", { name: "Stop using it" }));
    await waitFor(() => expect(api.setGeoIp).toHaveBeenLastCalledWith(null));
  });

  it("explains why a file was refused", async () => {
    mockApiDefaults();
    vi.mocked(api.setGeoIp).mockRejectedValue(new Error("That file is not a location database (.mmdb)."));
    render(<GeoIpCard />);
    await userEvent.type(await screen.findByLabelText(/Full path/), "C:\\x.mmdb");
    await userEvent.click(screen.getByRole("button", { name: "Use this database" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("not a location database");
  });

  it("shows where an alert's address is", async () => {
    mockApiDefaults();
    vi.mocked(api.getAlert).mockResolvedValue({
      id: 5, alert_id: "ALT-000005", rule_id: "HZ-019", rule_name: "Impossible travel", severity: "high", status: "OPEN", description: "d",
      source_ip: "8.8.2.2", username: "alice", occurrences: 2, window_minutes: 1440, techniques: [], created_at: "2026-11-24T09:00:00",
      last_seen: "2026-11-24T09:00:00", intel: null, events: [], history: [], assignee: null, tags: [], age_minutes: 1, sla_minutes: 240,
      sla_breached: false, iocs: [], geo: { country_code: "JP", country: "Japan", city: "Tokyo" } });
    render(<MemoryRouter><AlertDrawer alertId={5} onClose={() => {}} /></MemoryRouter>);
    expect(await screen.findByText("Tokyo, Japan")).toBeInTheDocument();
  });
});
