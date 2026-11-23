import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import usePolling from "./usePolling.js";

afterEach(() => vi.useRealTimers());

describe("usePolling", () => {
  it("loads data and clears the loading flag", async () => {
    const fn = vi.fn().mockResolvedValue({ n: 1 });
    const { result } = renderHook(() => usePolling(fn, []));
    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.data).toEqual({ n: 1 }));
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it("captures the error message instead of throwing", async () => {
    const fn = vi.fn().mockRejectedValue(new Error("API is down"));
    const { result } = renderHook(() => usePolling(fn, []));
    await waitFor(() => expect(result.current.error).toBe("API is down"));
    expect(result.current.loading).toBe(false);
    expect(result.current.data).toBeNull();
  });

  it("refreshes on the interval and stops after unmount", async () => {
    vi.useFakeTimers();
    const fn = vi.fn().mockResolvedValue("ok");
    const { unmount } = renderHook(() => usePolling(fn, [], 1000));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(fn).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(fn).toHaveBeenCalledTimes(4);
    unmount();
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(fn).toHaveBeenCalledTimes(4);
  });

  it("reloads when its dependencies change", async () => {
    const fn = vi.fn().mockImplementation(async () => "x");
    const { rerender } = renderHook(({ page }) => usePolling(fn, [page]), { initialProps: { page: 1 } });
    await waitFor(() => expect(fn).toHaveBeenCalledTimes(1));
    rerender({ page: 2 });
    await waitFor(() => expect(fn).toHaveBeenCalledTimes(2));
  });

  it("recovers after an error on the next successful refresh", async () => {
    vi.useFakeTimers();
    const fn = vi.fn().mockRejectedValueOnce(new Error("blip")).mockResolvedValue("fine");
    const { result } = renderHook(() => usePolling(fn, [], 1000));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(result.current.error).toBe("blip");
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(result.current.data).toBe("fine");
    expect(result.current.error).toBeNull();
  });
});
