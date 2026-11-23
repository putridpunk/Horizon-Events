# Corporate UI Redesign — Design

Date: 2026-11-23. Requested by the user: a straight, corporate, professional UI that stays as user-friendly as possible. The tool stays local-use (no accounts or logins). Light by default with a dark toggle (user's choice).

## Intent

Replace the neon "cyber" look with a sober enterprise look, and take the opportunity to remove friction: clearer navigation, triage-first Overview, readable times, accessible severity, consistent controls. Frontend only: no backend, API or data changes.

## Goals

- Calm, consistent visual system: one accent, neutral surfaces, restrained borders, no glow, gradients or neon.
- Light theme by default; dark theme via a toggle in the top bar; the choice is remembered in the browser (`localStorage`, with a safe fallback when storage is blocked).
- A **Data sources** page (under Monitor) and a first-run setup screen for the system-log collection described in `2026-11-23-desktop-and-system-logs-design.md`.
- A user-friendlier shell: grouped sidebar (Monitor, Respond, Insight) with icons; a top bar with the page title, live-monitoring state, theme toggle and a global **Import logs** action (today it exists only on Overview).
- A triage-first Overview: KPI cards (events, open alerts, open incidents, critical alerts) and a **Needs attention** panel (open critical and high alerts, and incidents not yet investigated) linking straight to the item.
- Severity and status never rely on colour alone: label plus icon.
- Relative times ("12 min ago") with the exact timestamp on hover; older items show a date.
- Better empty states (what this page shows, what to do next), loud-and-clear errors, Esc closes drawers and dialogs, visible keyboard focus, AA contrast in both themes.
- Charts re-coloured from the active theme.

## Non-goals

Accounts or authentication, backend changes, new pages or features, new runtime dependencies (icons are inline SVG; fonts are the system stack, so nothing is fetched from the network), custom user themes, internationalisation.

## Approaches considered

- **CSS-variable design tokens with a theme attribute (chosen):** the app already styles through variables; `data-theme` on the root swaps a token set. No new dependencies.
- **A component library (MUI, Ant, Fluent):** heavy, changes bundle size and every component. Rejected.
- **Utility CSS framework (Tailwind):** a new build dependency and a rewrite of all markup. Rejected.

## Design

### Tokens (light / dark)

| Token | Light | Dark |
| --- | --- | --- |
| page background | `#f4f6f9` | `#0f141b` |
| surface (cards, tables) | `#ffffff` | `#161c26` |
| border | `#dfe3ea` | `#263041` |
| text | `#1f2937` | `#e6e9ee` |
| muted text | `#5b6574` | `#9aa5b4` |
| sidebar | `#14213d` (text `#cbd5e1`) | `#0b1018` (text `#aab4c3`) |
| accent | `#1f5fbf` | `#5b9cf5` |
| critical / high / medium / low | red `#b42318`, orange `#b54708`, amber `#8a6a00`, blue `#1d5fa5` on tinted backgrounds | lighter equivalents on dark tints |
| success (live, resolved) | `#1a7f4b` | `#5fd08f` |

All text and badge pairs must meet WCAG AA contrast (4.5:1 for text). Typography: system UI font stack, 14px base with 1.5 line height, 22/16 headings, monospace only for IDs, IPs and raw logs. Spacing on a 4px scale. **Squarer corners (user feedback: heavy rounding looks generated):** radius 2px for buttons, inputs and badges, 4px for cards, 0 for tables, drawers and the sidebar; no pill shapes anywhere (the Live indicator and status badges are rectangular tags). One hairline border weight; no shadows except focus rings and drawers.

### Components

- **Theme provider and toggle:** sets `data-theme` on `<html>`, remembers the choice, exposes the active theme to charts.
- **Severity badge:** icon plus label (critical, high, medium, low). **Status badge:** open (red dot), investigating (amber), resolved (green check).
- **Time:** relative for under 7 days, absolute date otherwise, exact timestamp as `title`.
- **Buttons:** one primary per view, secondary outlined, plain for tertiary; consistent sizes; icons only where they add clarity.
- **Tables:** sticky header, 44px rows, subtle row hover, a chevron on clickable rows, readable columns (no all-caps headers).
- **Drawers and dialogs:** sticky header with the item ID and a close button, Esc to close, focus moved into the drawer on open.
- **Empty and error states:** short title, one sentence of help, a next action where one exists.

### Layout

Sidebar 232px (collapses to a top bar under 900px). Content max width about 1280px, centred. Overview order: KPI row, Needs attention, events-over-time chart, latest alerts, live monitoring card.

## Testing

Existing 75 tests keep guarding behaviour and are updated where text or structure changes. New tests: theme toggle sets the attribute, persists and survives blocked storage; relative-time formatting and boundaries; severity and status badges expose text labels; Needs attention lists the right items and links; Esc closes drawers; global Import logs works from any page. Manual checks in light and dark: contrast, keyboard navigation, 1280px and 900px widths, and screenshots for the README.

## Left to the builder

Exact icon set drawings, minor spacing values, and chart colour assignments beyond the token table, as long as they respect the tokens above.
