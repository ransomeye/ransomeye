import { Outlet, NavLink } from "react-router-dom";
import {
  ShieldCheck,
  Activity,
  AlertTriangle,
  Radio,
  Lock,
  LayoutDashboard,
  FileWarning,
  Scale,
  Server,
  ClipboardCheck,
  Brain,
  Shield,
  Zap,
  EyeOff,
  Radar,
  TrendingUp,
  Database,
} from "lucide-react";
import { SocContextStrip } from "./SocContextStrip";
import { AppHeader } from "./AppHeader";

export function Layout() {
  return (
    <div className="app-layout">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="sidebar-brand">
          <h2 className="text-gradient sidebar-title-row">
            <ShieldCheck size={28} aria-hidden />
            RansomEye
          </h2>
          <p className="sidebar-product-line">Security operations command center</p>
        </div>

        <div className="sidebar-security-badge">
          <Lock size={14} aria-hidden />
          Private session · TLS 1.3 · mutual authentication
        </div>

        <div className="nav-section-label">Command center</div>
        <nav className="flex-col-gap-4" aria-label="Operations">
          <NavLink to="/dashboard" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`} id="nav-dashboard">
            <LayoutDashboard size={18} aria-hidden />
            Command center
          </NavLink>
          <NavLink to="/event-feed" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`} id="nav-event-feed">
            <Radio size={18} aria-hidden />
            Live telemetry
          </NavLink>
          <NavLink to="/alerts" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`} id="nav-alerts">
            <AlertTriangle size={18} aria-hidden />
            Alert queue
          </NavLink>
          <NavLink to="/incidents" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`} id="nav-incidents-panel">
            <FileWarning size={18} aria-hidden />
            Incidents
          </NavLink>
          <NavLink to="/health" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`} id="nav-system-health">
            <Activity size={18} aria-hidden />
            Operational health
          </NavLink>
        </nav>

        <div className="nav-section-label nav-section-label--spaced">Investigation</div>
        <nav className="flex-col-gap-4" aria-label="Investigation">
          <NavLink to="/detections" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`} id="nav-detections">
            <Zap size={18} aria-hidden />
            Detections
          </NavLink>
          <NavLink to="/explainability" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`} id="nav-explainability">
            <Brain size={18} aria-hidden />
            Explainability
          </NavLink>
          <NavLink to="/stream" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`} id="nav-stream">
            <Shield size={18} aria-hidden />
            Stream review
          </NavLink>
        </nav>

        <div className="nav-section-label nav-section-label--spaced">Posture</div>
        <nav className="flex-col-gap-4" aria-label="Risk and posture">
          <NavLink to="/fleet" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`} id="nav-fleet">
            <Server size={18} aria-hidden />
            Endpoint roster
          </NavLink>
          <NavLink to="/asset-coverage" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`} id="nav-assets">
            <Radar size={18} aria-hidden />
            Asset coverage
          </NavLink>
          <NavLink to="/ingestion" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`} id="nav-ingestion">
            <Database size={18} aria-hidden />
            Data flow
          </NavLink>
          <NavLink to="/compliance" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`} id="nav-compliance">
            <ClipboardCheck size={18} aria-hidden />
            Compliance
          </NavLink>
          <NavLink to="/governance" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`} id="nav-governance">
            <Scale size={18} aria-hidden />
            Governance
          </NavLink>
        </nav>

        <div className="nav-section-label nav-section-label--spaced">Executive</div>
        <nav className="flex-col-gap-4" aria-label="Executive">
          <NavLink to="/executive" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`} id="nav-executive">
            <TrendingUp size={18} aria-hidden />
            Executive summary
          </NavLink>
        </nav>

        <div className="nav-section-label nav-section-label--spaced">Advisory</div>
        <nav className="flex-col-gap-4" aria-label="Advisory models">
          <NavLink
            to="/shadow-intelligence"
            className={({ isActive }) => `nav-link nav-link--advisory ${isActive ? "active" : ""}`}
            id="nav-shadow"
          >
            <EyeOff size={18} aria-hidden />
            Advisory intelligence
          </NavLink>
        </nav>

        <div className="sidebar-version">Air-gapped deployment · read-only console</div>
      </aside>
      <div className="main-content">
        <AppHeader />
        <SocContextStrip />
        <Outlet />
      </div>
    </div>
  );
}
