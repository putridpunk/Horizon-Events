import { useEffect, useState } from "react";

const KEY = "horizon-theme";
const listeners = new Set();

const normalise = (value) => (value === "dark" ? "dark" : "light");

export function getTheme() {
  return normalise(document.documentElement.getAttribute("data-theme"));
}

/** Apply the remembered theme (light unless the user chose dark). Never throws: storage may be blocked. */
export function initTheme() {
  let stored = null;
  try {
    stored = localStorage.getItem(KEY);
  } catch {
    /* blocked storage: stay on the default */
  }
  document.documentElement.setAttribute("data-theme", normalise(stored));
}

export function setTheme(value) {
  if (value !== "light" && value !== "dark") return;
  document.documentElement.setAttribute("data-theme", value);
  try {
    localStorage.setItem(KEY, value);
  } catch {
    /* the choice still applies for this session */
  }
  listeners.forEach((fn) => fn(value));
}

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function useTheme() {
  const [theme, setCurrent] = useState(getTheme);
  useEffect(() => subscribe(setCurrent), []);
  return [theme, setTheme];
}
