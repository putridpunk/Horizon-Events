# Corporate UI Implementation Plan (project 3 of 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the neon look with a sober, squarer enterprise UI (light by default, dark toggle) and add the usability improvements from the design.

**Architecture:** CSS-variable design tokens keyed by `data-theme`; a small theme module; shared presentational components (icons, badges, time, buttons, tables) that every page reuses; chart colours read from the active theme.

**Tech Stack:** React, plain CSS variables, inline SVG icons. No new dependencies, no web fonts.

**Spec:** `docs/superpowers/specs/2026-11-23-corporate-ui-design.md`

## Global Constraints

- Tokens (light / dark): page `#f4f6f9` / `#0f141b`; surface `#ffffff` / `#161c26`; border `#dfe3ea` / `#263041`; text `#1f2937` / `#e6e9ee`; muted `#5b6574` / `#9aa5b4`; sidebar `#14213d` / `#0b1018`; accent `#1f5fbf` / `#5b9cf5`; critical `#b42318` / `#ff8a80`, high `#b54708` / `#ffb36b`, medium `#8a6a00` / `#f2cf5b`, low `#1d5fa5` / `#7db6f0`, success `#1a7f4b` / `#5fd08f`. Severity and status tints as in the approved mockup.
- Radius: 2px buttons, inputs and badges; 4px cards; 0 for tables, drawers and the sidebar; no pill shapes. No gradients, glows or decorative shadows; shadows only for focus rings and drawers.
- Type: system font stack, 14px base, 1.5 line height, headings 22/16, monospace only for IDs, IPs and raw logs. Text contrast at least 4.5:1 in both themes.
- Theme stored in `localStorage` key `horizon-theme` (values `light` or `dark`), default `light`, applied before first paint (inline script in `index.html`); storage errors fall back to light silently.
- Severity and status always carry a text label and an icon. Times: under 1 min "just now", under 60 min "N min ago", under 24 h "N h ago", under 7 d "N d ago", otherwise a date; the exact timestamp is the `title`.
- All 75+ existing frontend tests stay green (update their expectations where text or structure changes). Run with `npm test` in `frontend/` (Node from the pip-provided toolchain).

## Review Focus

- Both themes: every text, badge, border and chart colour is legible (spot-check contrast numerically for the token pairs).
- Dark and light screens have no leftover hard-coded colours (search `theme.css` and components for hex values outside the token block).
- Blocked or throwing `localStorage` does not crash the app or flash the wrong theme.
- Esc closes drawers and dialogs, focus moves into a drawer when it opens and returns to the row, keyboard focus is always visible, controls reachable by Tab in logical order.
- Empty database, API down and loading states still render in every page.
- Narrow window (about 900px wide) is usable: sidebar collapses, tables scroll horizontally instead of breaking the page.

---

### Task 1: Tokens, theme module and shared base

**Files:**
- Create: `frontend/src/theme/theme.js`, `frontend/src/theme/ThemeToggle.jsx`, `frontend/src/theme/useChartColors.js`, `frontend/src/theme/theme.test.jsx`
- Modify: `frontend/src/theme.css` (rewrite as tokens plus base elements), `frontend/index.html` (pre-paint theme script), `frontend/src/main.jsx`

**Interfaces:**
- `getTheme() -> "light" | "dark"`, `setTheme(value)` (writes the attribute on `<html>` and storage, notifies subscribers), `subscribe(fn) -> unsubscribe`, `useTheme() -> [theme, setTheme]`; `<ThemeToggle />` (button with an accessible label that names the target theme); `useChartColors() -> { text, grid, accent, critical, high, medium, low, surface }` read from CSS variables and refreshed on theme change.

- [ ] **Step 1: Write failing tests**: default is light; toggle flips the attribute and persists; stored value is restored; invalid stored value falls back to light; throwing storage does not crash; subscribers are notified; `useChartColors` changes with the theme (jsdom with a stub stylesheet).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** the module and the full token CSS (including `[data-theme="dark"]`, focus ring, scrollbars, buttons, inputs, tables, cards, drawers, badges). **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: design tokens and theme toggle`.

### Task 2: Shared components

**Files:**
- Create: `frontend/src/components/ui/{Icon,SeverityBadge,StatusBadge,Time,EmptyState,PageHeader,Button}.jsx`, `frontend/src/components/ui/ui.test.jsx`, `frontend/src/lib/time.js`, `frontend/src/lib/time.test.js`
- Modify: `frontend/src/components/common.jsx` (re-export the new components so existing imports keep working)

**Interfaces:**
- `Icon({ name, size })` for: dashboard, list, bell, folders, chart, file, upload, sun, moon, chevron-right, close, alert, arrow-up, arrow-down, minus, check, shield, refresh, play, pause, search. `SeverityBadge({ value })` → icon plus capitalised label; `StatusBadge({ value })` for `OPEN`, `INVESTIGATING`, `RESOLVED` (dot or check plus label). `formatRelative(iso, now = Date.now()) -> { text, exact }` and `<Time value now />`. `EmptyState({ title, children, action })`. `Button({ variant: "primary"|"secondary"|"plain", ... })`.

- [ ] **Step 1: Write failing tests**: relative-time boundaries (0 s, 59 s, 60 s, 59 min, 60 min, 23 h 59 min, 24 h, 6 d, 7 d, future timestamps clamp to "just now", invalid input renders "-"); badges expose text labels for all four severities and three statuses; icons are `aria-hidden` unless labelled.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: shared UI components`.

### Task 3: Application shell

**Files:**
- Create: `frontend/src/components/shell/{Sidebar,TopBar}.jsx`, `frontend/src/components/shell/shell.test.jsx`
- Modify: `frontend/src/components/Layout.jsx`, `frontend/src/components/ImportButton.jsx` (compact for the top bar)

**Interfaces:**
- Sidebar groups: Monitor (Overview, Events, Data sources), Respond (Alerts, Incidents), Insight (Analytics, Reports), with icons and an active state; collapses to a top strip below 900px. TopBar: page title from the route, a rectangular **Live** indicator (collecting when the collectors API reports any collecting source or the watch folder is live; otherwise "Not collecting"), `ThemeToggle`, and the global **Import logs** button.

- [ ] **Step 1: Write failing tests**: all links render under the right groups; active link marked; title follows the route; Import logs present on every route; indicator states from mocked API; keyboard Tab order.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: sidebar and top bar`.

### Task 4: Overview with Needs attention

**Files:**
- Modify: `frontend/src/pages/Overview.jsx`, `frontend/src/charts/charts.jsx` (theme colours); `frontend/src/pages/screens.test.jsx` (update)
- Create: `frontend/src/components/AttentionPanel.jsx`, `frontend/src/components/AttentionPanel.test.jsx`

**Interfaces:**
- KPI cards: events collected, open alerts, open incidents, critical alerts (open incident count from `listIncidents({status:"OPEN", limit:1}).total`, critical from `getOverview`). `AttentionPanel`: open alerts with severity critical then high (`listAlerts` for each, merged, newest first, at most 6) plus incidents still `OPEN` (at most 4); rows link to the item (alert drawer or incident drawer through router state or query parameter); an all-clear state when there is nothing.

- [ ] **Step 1: Write failing tests**: panel ordering (critical before high), the limit, links open the right drawer, all-clear state, error state, loading state; Overview empty database (zeros, empty states, no crash).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: overview with Needs attention`.

### Task 5: Restyle all pages and drawers

**Files:**
- Modify: `frontend/src/pages/{Events,Alerts,Incidents,Analytics,Reports,Sources,Setup}.jsx`, `frontend/src/components/{AlertDrawer,IncidentDrawer,EventDetail,ModelCard,IntelCard,LiveCard,MitrePanel,TechniqueBadges,IntelBadge}.jsx` and their tests
- Create: `frontend/src/components/Drawer.jsx` (shared drawer: sticky header, Esc, focus handling), `frontend/src/components/Drawer.test.jsx`

**Interfaces:**
- `Drawer({ title, subtitle, onClose, children })`: Esc and backdrop close, focus moves in on open and returns to the opener on close, `role="dialog"` with `aria-labelledby`. Tables: sticky header, 44px rows, hover, chevron on clickable rows, relative `Time`, `SeverityBadge`/`StatusBadge` everywhere. Buttons use `Button` (one primary per view). Empty states use `EmptyState` with a next step. Existing behaviour and API calls do not change.

- [ ] **Step 1: Write failing tests**: Esc closes each drawer, focus enters and returns, dialog roles and labels, times render relative with exact `title`, badges have labels; keep all existing behavioural tests passing.
- [ ] **Step 2: Run** → FAIL. **Step 3: Restyle and refactor** page by page. **Step 4: Run** the whole frontend suite and build → PASS.
- [ ] **Step 5: Commit** `feat: corporate styling across pages and drawers`.

### Task 6: Accessibility pass, screenshots, executable check

**Files:**
- Modify: `README.md`, `docs/screenshots/*`

- [ ] **Step 1: Contrast check**: compute WCAG ratios for the token pairs in both themes (text on page and surface, muted on surface, each badge text on its tint, accent button text) with a small script; fix any pair under 4.5:1.
- [ ] **Step 2: Manual pass** in the built app, light and dark, at 1440px and 900px: keyboard-only walk through Overview, an alert drawer and an incident drawer; confirm focus rings, Esc, no horizontal page scroll.
- [ ] **Step 3: Recapture the README screenshots** with the sample data only (Overview light, alert drawer, incident drawer, Analytics, one dark-theme shot), checking each image for personal data (use the neutral `X:` mapping trick for the data folder).
- [ ] **Step 4: Rebuild the executable** and run the full backend and frontend suites.
- [ ] **Step 5: Commit** `docs: screenshots for the corporate UI`.
