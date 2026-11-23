import { NavLink } from "react-router-dom";
import Icon from "../ui/Icon.jsx";
import { NAV_GROUPS } from "./routes.js";

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="brand-mark"><Icon name="shield" size={15} /></span>
        <div>Horizon Events<small>Security monitoring</small></div>
      </div>
      <nav className="nav" aria-label="Main">
        {NAV_GROUPS.map(([group, links]) => (
          <div className="nav-group" key={group}>
            <div className="nav-label">{group}</div>
            {links.map(([to, label, icon]) => (
              <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => (isActive ? "active" : "")}>
                <Icon name={icon} />
                {label}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
    </aside>
  );
}
