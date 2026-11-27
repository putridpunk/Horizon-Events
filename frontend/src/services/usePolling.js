import { useCallback, useEffect, useRef, useState } from "react";
import { subscribeLive } from "./live.js";

/** Load data with `fn`, re-run when `deps` change, and optionally refresh every `intervalMs`. */
export default function usePolling(fn, deps, intervalMs = 0) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const load = useCallback(async () => {
    try {
      setData(await fnRef.current());
      setError(null);
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    load();
    if (!intervalMs) return undefined;
    const id = setInterval(load, intervalMs);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, intervalMs, load]);

  // Screens that refresh on a timer also refresh the moment the server says something changed.
  useEffect(() => {
    if (!intervalMs) return undefined;
    let timer = null;
    const unsubscribe = subscribeLive(() => {
      clearTimeout(timer);
      timer = setTimeout(load, 250);  // a burst of changes becomes one refresh
    });
    return () => { clearTimeout(timer); unsubscribe(); };
  }, [intervalMs, load]);

  return { data, error, loading, reload: load };
}
