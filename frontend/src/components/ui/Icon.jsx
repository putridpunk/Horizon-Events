// Small outline icons drawn inline (24x24, 1.75 stroke): no icon font or network request is needed.
const PATHS = {
  dashboard: <><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /></>,
  list: <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />,
  bell: <path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0" />,
  folders: <path d="M3 6h6l2 2h10v11H3z" />,
  database: <><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" /></>,
  chart: <path d="M4 20V10M10 20V4M16 20v-8M22 20H2" />,
  file: <path d="M6 3h8l5 5v13H6zM14 3v5h5" />,
  upload: <path d="M12 16V4M7 9l5-5 5 5M4 20h16" />,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>,
  moon: <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />,
  "chevron-right": <path d="M9 6l6 6-6 6" />,
  close: <path d="M6 6l12 12M18 6L6 18" />,
  alert: <path d="M12 3l10 18H2zM12 10v5M12 18h.01" />,
  "arrow-up": <path d="M12 19V5M5 12l7-7 7 7" />,
  "arrow-down": <path d="M12 5v14M5 12l7 7 7-7" />,
  minus: <path d="M5 12h14" />,
  check: <path d="M5 13l4 4L19 7" />,
  shield: <path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" />,
  refresh: <path d="M20 11a8 8 0 0 0-14.9-3M4 4v4h4M4 13a8 8 0 0 0 14.9 3M20 20v-4h-4" />,
  search: <><circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
};

export const ICON_NAMES = Object.keys(PATHS);

/** Decorative by default (aria-hidden). Pass `label` when the icon is the only thing conveying meaning. */
export default function Icon({ name, size = 16, label }) {
  const shape = PATHS[name];
  if (!shape) return null;
  return (
    <svg className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"
      {...(label ? { role: "img", "aria-label": label } : { "aria-hidden": "true", focusable: "false" })}>
      {shape}
    </svg>
  );
}
