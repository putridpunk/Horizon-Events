// One shared server-sent-events connection: the server says when events, alerts or incidents changed, and any
// screen that refreshes on a timer also refreshes at once. If the connection fails the browser retries by itself,
// and the timers keep the screens fresh in the meantime.
const listeners = new Set();
let source = null;
const RETRY_MS = 5000;

function open() {
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
  // The browser retries a dropped connection by itself, but gives up for good on a refusal (for example when the
  // sign-in ended). Then we start a fresh connection a little later, for as long as any screen is listening.
  source.onerror = () => {
    if (source && source.readyState === 2) {
      source = null;
      setTimeout(() => { if (listeners.size && !source) open(); }, RETRY_MS);
    }
  };
}

export function subscribeLive(listener) {
  if (typeof EventSource === "undefined") return () => {};
  listeners.add(listener);
  if (!source) open();
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0 && source) {
      source.close();
      source = null;
    }
  };
}
