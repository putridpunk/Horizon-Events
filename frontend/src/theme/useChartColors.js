import { useMemo } from "react";
import { useTheme } from "./theme.js";

// Used only if the stylesheet is missing (for example in tests): readable on both themes.
const FALLBACK = {
  text: "#5b6574", grid: "#dfe3ea", accent: "#1f5fbf", critical: "#b42318", high: "#b54708",
  medium: "#8a6a00", low: "#1d5fa5", surface: "#ffffff",
};
const VARIABLES = {
  text: "--muted", grid: "--border", accent: "--accent", critical: "--critical", high: "--high",
  medium: "--medium", low: "--low", surface: "--surface",
};

/** Chart colours taken from the active theme's CSS variables; recomputed when the theme changes. */
export default function useChartColors() {
  const [theme] = useTheme();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  return useMemo(() => {
    const style = getComputedStyle(document.documentElement);
    return Object.fromEntries(Object.entries(VARIABLES).map(([key, variable]) => {
      const value = style.getPropertyValue(variable).trim();
      return [key, /^#[0-9a-f]{6}$/i.test(value) ? value : FALLBACK[key]];
    }));
  }, [theme]);
}
