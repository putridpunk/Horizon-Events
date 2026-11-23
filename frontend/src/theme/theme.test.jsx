import { act, fireEvent, render, renderHook, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import ThemeToggle from "./ThemeToggle.jsx";
import { getTheme, initTheme, setTheme, subscribe, useTheme } from "./theme.js";
import useChartColors from "./useChartColors.js";

const root = document.documentElement;

beforeEach(() => {
  localStorage.clear();
  root.removeAttribute("data-theme");
  root.removeAttribute("style");
});
afterEach(() => vi.restoreAllMocks());

describe("theme module", () => {
  it("defaults to light", () => {
    initTheme();
    expect(getTheme()).toBe("light");
    expect(root.getAttribute("data-theme")).toBe("light");
  });

  it("restores a stored dark choice", () => {
    localStorage.setItem("horizon-theme", "dark");
    initTheme();
    expect(getTheme()).toBe("dark");
  });

  it("falls back to light for any other stored value", () => {
    localStorage.setItem("horizon-theme", "solarized");
    initTheme();
    expect(getTheme()).toBe("light");
  });

  it("setTheme updates the attribute, persists it and notifies subscribers", () => {
    const seen = [];
    const off = subscribe((t) => seen.push(t));
    setTheme("dark");
    setTheme("light");
    off();
    setTheme("dark");
    expect(seen).toEqual(["dark", "light"]);  // unsubscribed before the last call
    expect(localStorage.getItem("horizon-theme")).toBe("dark");
  });

  it("ignores invalid values", () => {
    setTheme("neon");
    expect(getTheme()).toBe("light");
  });

  it("survives storage that throws (private mode, blocked storage)", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("blocked"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("blocked"); });
    expect(() => initTheme()).not.toThrow();
    expect(getTheme()).toBe("light");
    expect(() => setTheme("dark")).not.toThrow();
    expect(getTheme()).toBe("dark");  // still applies for this session
  });

  it("useTheme follows changes made elsewhere", () => {
    const { result } = renderHook(() => useTheme());
    expect(result.current[0]).toBe("light");
    act(() => setTheme("dark"));
    expect(result.current[0]).toBe("dark");
  });
});

describe("ThemeToggle", () => {
  it("names the theme it switches to and flips on click", () => {
    initTheme();
    render(<ThemeToggle />);
    const button = screen.getByRole("button", { name: "Switch to dark theme" });
    fireEvent.click(button);
    expect(getTheme()).toBe("dark");
    expect(screen.getByRole("button", { name: "Switch to light theme" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Switch to light theme" }));
    expect(getTheme()).toBe("light");
  });
});

describe("useChartColors", () => {
  it("reads the colours from the active theme and updates when it changes", () => {
    root.style.setProperty("--accent", "#111111");
    root.style.setProperty("--critical", "#222222");
    const { result } = renderHook(() => useChartColors());
    expect(result.current.accent).toBe("#111111");
    expect(result.current.critical).toBe("#222222");
    root.style.setProperty("--accent", "#333333");
    act(() => setTheme("dark"));
    expect(result.current.accent).toBe("#333333");
  });

  it("falls back to safe colours when the stylesheet is missing", () => {
    const { result } = renderHook(() => useChartColors());
    for (const key of ["text", "grid", "accent", "critical", "high", "medium", "low", "surface"]) {
      expect(result.current[key]).toMatch(/^#[0-9a-f]{6}$/i);
    }
  });
});
