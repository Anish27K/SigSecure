import React from "react";
import { Home, UploadCloud, List, Settings, ChevronLeft, ChevronRight } from "lucide-react";

/**
 * Props:
 *  - active (string) current active view: "home"|"verify"|"history"|"settings"
 *  - onNavigate(name) callback when a nav item clicked
 */
export default function Sidebar({ active = "verify", onNavigate = () => {} }) {
  const [collapsed, setCollapsed] = React.useState(false);

  const NavItem = ({ id, Icon, label }) => {
    const isActive = id === active;
    return (
      <button
        onClick={() => onNavigate(id)}
        className={
          "nav-item " +
          (isActive ? "nav-item--active" : "") +
          (collapsed ? " nav-item--collapsed" : "")
        }
        title={label}
      >
        <span className="nav-icon">
          {Icon ? <Icon size={18} /> : label.charAt(0).toUpperCase()}
        </span>
        {!collapsed && <span className="nav-label">{label}</span>}
      </button>
    );
  };

  return (
    <aside className={`sidebar ${collapsed ? "sidebar--collapsed" : ""}`}>
      <div className="sidebar-top">
        <div className="sidebar-brand" onClick={() => onNavigate("home")}>
          <div className="brand-mark">S</div>
          {!collapsed && <div className="brand-text">SigSecure</div>}
        </div>
        <button
          className="collapse-btn"
          onClick={() => setCollapsed((c) => !c)}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
        </button>
      </div>

      <nav className="sidebar-nav">
        <NavItem id="home" Icon={Home} label="Dashboard" />
        <NavItem id="verify" Icon={UploadCloud} label="Verify file" />
        <NavItem id="history" Icon={List} label="History" />
        <NavItem id="settings" Icon={Settings} label="Settings" />
      </nav>

      <div className="sidebar-footer">
        {!collapsed ? (
          <div className="footer-note">v1.0 • Local</div>
        ) : (
          <div className="footer-dot" />
        )}
      </div>
    </aside>
  );
}
