import { NavLink } from "react-router-dom";

const LINKS = [
  ["/", "Overview"],
  ["/events", "Events"],
  ["/alerts", "Alerts"],
  ["/incidents", "Incidents"],
  ["/sources", "Data sources"],
  ["/analytics", "Analytics"],
  ["/reports", "Reports"],
];

export default function Layout({ children }) {
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" />
          <div>
            HORIZON
            <small>EVENTS · SIEM</small>
          </div>
        </div>
        <nav className="nav">
          {LINKS.map(([to, label]) => (
            <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => (isActive ? "active" : "")}>
              {label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}
