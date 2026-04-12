import { Link, useLocation } from "react-router-dom";
import { ChevronRight, ShieldCheck } from "lucide-react";

const ROUTE_CRUMB: Record<string, { area: string; page: string }> = {
  "/dashboard": { area: "Command center", page: "Overview" },
  "/event-feed": { area: "Command center", page: "Live telemetry" },
  "/alerts": { area: "Command center", page: "Alert queue" },
  "/incidents-panel": { area: "Command center", page: "Incidents" },
  "/incidents": { area: "Command center", page: "Incidents" },
  "/system-health": { area: "Posture", page: "Operational health" },
  "/detections": { area: "Investigation", page: "Detections" },
  "/explainability": { area: "Investigation", page: "Explainability" },
  "/stream": { area: "Investigation", page: "Stream review" },
  "/fleet": { area: "Posture", page: "Endpoint roster" },
  "/asset-coverage": { area: "Posture", page: "Asset coverage" },
  "/ingestion": { area: "Posture", page: "Data flow" },
  "/compliance": { area: "Posture", page: "Compliance" },
  "/governance": { area: "Posture", page: "Governance" },
  "/executive": { area: "Executive", page: "Summary" },
  "/shadow-intelligence": { area: "Advisory", page: "Model intelligence" },
  "/health": { area: "Posture", page: "Operational health" },
};

export function AppHeader() {
  const { pathname } = useLocation();
  const crumb = ROUTE_CRUMB[pathname] ?? { area: "Console", page: "Home" };

  return (
    <header className="soc-app-header" aria-label="Location">
      <nav className="soc-breadcrumb" aria-label="Breadcrumb">
        <Link to="/dashboard" className="soc-breadcrumb__root">
          Command center
        </Link>
        <ChevronRight size={14} className="soc-breadcrumb__sep" aria-hidden />
        <span className="soc-breadcrumb__area">{crumb.area}</span>
        <ChevronRight size={14} className="soc-breadcrumb__sep" aria-hidden />
        <span className="soc-breadcrumb__page">{crumb.page}</span>
      </nav>
      <div className="soc-app-header__meta">
        <span className="soc-env-pill" title="Deployment context">
          <ShieldCheck size={14} aria-hidden />
          Air-gapped security operations
        </span>
      </div>
    </header>
  );
}
