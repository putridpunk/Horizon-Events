// One shared server-sent-events connection: the server says when events, alerts or incidents changed, and any
// screen that refreshes on a timer also refreshes at once. If the connection fails the browser retries by itself,
// and the timers keep the screens fresh in the meantime.
const listeners = new Set();
let source = null;

export function subscribeLive(listener) {
  if (typeof EventSource === "undefined") return () => {};
  listeners.add(listener);
  if (!source) {
    source = new EventSource("/api/stream");
    source.addEventListener("change", (e) => {
      let changed = [];
      try {
        changed = JSON.parse(e.data).changed ?? [];
      } catch {
        /* a malformed message still means "something changed" */
      }
      listeners.forEach((l) => l(changed));
    });
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0 && source) {
      source.close();
      source = null;
    }
  };
}
