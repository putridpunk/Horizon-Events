import { describe, expect, it } from "vitest";
import { formatRelative, parseTimestamp } from "./time.js";

const NOW = Date.parse("2026-11-23T12:00:00Z");
const ago = (seconds) => new Date(NOW - seconds * 1000).toISOString();
const rel = (seconds) => formatRelative(ago(seconds), NOW).text;

describe("parseTimestamp", () => {
  it("treats timestamps without a timezone as UTC, like the backend stores them", () => {
    expect(parseTimestamp("2026-11-23T12:00:00").getTime()).toBe(Date.parse("2026-11-23T12:00:00Z"));
    expect(parseTimestamp("2026-11-23T12:00:00.123456").getTime()).toBe(Date.parse("2026-11-23T12:00:00.123Z"));
  });

  it("respects an explicit offset", () => {
    expect(parseTimestamp("2026-11-23T12:00:00+02:00").getTime()).toBe(Date.parse("2026-11-23T10:00:00Z"));
    expect(parseTimestamp("2026-11-23T12:00:00Z").getTime()).toBe(Date.parse("2026-11-23T12:00:00Z"));
  });

  it("returns null for missing or invalid values", () => {
    for (const bad of [null, undefined, "", "not a date", 12345]) expect(parseTimestamp(bad)).toBeNull();
  });
});

describe("formatRelative", () => {
  it.each([
    [0, "just now"], [59, "just now"],
    [60, "1 min ago"], [3599, "59 min ago"],
    [3600, "1 h ago"], [86399, "23 h ago"],
    [86400, "1 d ago"], [6 * 86400 + 86399, "6 d ago"],
  ])("%i seconds ago reads %s", (seconds, text) => {
    expect(rel(seconds)).toBe(text);
  });

  it("switches to a date at seven days", () => {
    const text = rel(7 * 86400);
    expect(text).not.toMatch(/ago|just now/);
    expect(text).toMatch(/2026/);
  });

  it("clamps future timestamps (clock skew) to 'just now'", () => {
    expect(formatRelative(new Date(NOW + 5 * 60 * 1000).toISOString(), NOW).text).toBe("just now");
  });

  it("exposes the exact local timestamp for hovering", () => {
    expect(formatRelative(ago(120), NOW).exact).toBe(new Date(NOW - 120000).toLocaleString());
  });

  it("shows a dash for missing or invalid input", () => {
    expect(formatRelative(null, NOW)).toEqual({ text: "-", exact: "" });
    expect(formatRelative("garbage", NOW)).toEqual({ text: "-", exact: "" });
  });
});
