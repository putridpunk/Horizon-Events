import { afterEach, describe, expect, it, vi } from "vitest";
import * as api from "./api.js";

const ok = (body) => ({ ok: true, status: 200, json: async () => body });
const fail = (status, body) => ({ ok: false, status, json: async () => body });

function mockFetch(response) {
  const fetchMock = vi.fn().mockResolvedValue(response);
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => vi.unstubAllGlobals());

describe("api client", () => {
  it("returns parsed JSON from /api paths", async () => {
    const f = mockFetch(ok({ total_events: 3 }));
    await expect(api.getOverview()).resolves.toEqual({ total_events: 3 });
    expect(f).toHaveBeenCalledWith("/api/statistics/overview", {});
  });

  it("omits empty and undefined query parameters", async () => {
    const f = mockFetch(ok({ items: [], total: 0 }));
    await api.listEvents({ q: "", severity: "high", source: undefined, event_type: null, limit: 25, offset: 0 });
    expect(f.mock.calls[0][0]).toBe("/api/events?severity=high&limit=25&offset=0");
  });

  it("throws the server's detail message for string errors", async () => {
    mockFetch(fail(422, { detail: "source_type must be one of: linux_auth" }));
    await expect(api.getAlert(1)).rejects.toThrow("source_type must be one of: linux_auth");
  });

  it("joins validation messages when detail is a list", async () => {
    mockFetch(fail(422, { detail: [{ msg: "field required" }, { msg: "value is not valid" }] }));
    await expect(api.updateAlert(1, {})).rejects.toThrow("field required; value is not valid");
  });

  it("falls back to a generic message when the error body is not JSON", async () => {
    mockFetch({ ok: false, status: 502, json: async () => { throw new Error("not json"); } });
    await expect(api.getOverview()).rejects.toThrow("Request failed (502)");
  });

  it("sends status updates as a JSON PATCH", async () => {
    const f = mockFetch(ok({}));
    await api.updateAlert(7, { status: "INVESTIGATING", note: "looking" });
    const [url, options] = f.mock.calls[0];
    expect(url).toBe("/api/alerts/7");
    expect(options.method).toBe("PATCH");
    expect(options.headers["Content-Type"]).toBe("application/json");
    expect(JSON.parse(options.body)).toEqual({ status: "INVESTIGATING", note: "looking" });
  });

  it("uploads logs as multipart form data", async () => {
    const f = mockFetch(ok({ imported: 1 }));
    const file = new File(["line"], "auth.log");
    await api.importLogs(file, "linux_auth");
    const [url, options] = f.mock.calls[0];
    expect(url).toBe("/api/imports");
    expect(options.method).toBe("POST");
    expect(options.body.get("source_type")).toBe("linux_auth");
    expect(options.body.get("file")).toBe(file);
  });

  it("uses DELETE to remove an alert from an incident and POST for merges", async () => {
    const f = mockFetch(ok({}));
    await api.removeIncidentAlert(2, 9);
    expect(f.mock.calls[0][0]).toBe("/api/incidents/2/alerts/9");
    expect(f.mock.calls[0][1].method).toBe("DELETE");
    await api.mergeIncident(2, 3);
    expect(JSON.parse(f.mock.calls[1][1].body)).toEqual({ into: 3 });
  });

  it("builds report download URLs", () => {
    expect(api.reportUrl("2026-11-01", "2026-12-01", "csv")).toBe("/api/reports?start=2026-11-01&end=2026-12-01&format=csv");
  });
});
