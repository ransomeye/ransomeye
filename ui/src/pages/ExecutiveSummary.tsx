import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight, BriefcaseBusiness, ShieldAlert, Users, Waves } from "lucide-react";
import {
  fetchAssetsCoverage,
  fetchDetectionsList,
  fetchFleetStatus,
  fetchIngestionStatus,
  fetchSystemHealth,
  getIncidents,
  type DetectionRow,
  type HealthResponse,
  type IncidentRow,
} from "../lib/client";

type CoveragePayload = {
  agents_registered?: number;
  agents_active_24h?: number;
  distinct_emitters_24h?: number;
};

export function ExecutiveSummary() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [ingestion, setIngestion] = useState<Record<string, unknown> | null>(null);
  const [detections, setDetections] = useState<DetectionRow[]>([]);
  const [incidents, setIncidents] = useState<IncidentRow[]>([]);
  const [coverage, setCoverage] = useState<CoveragePayload | null>(null);
  const [fleet, setFleet] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const [nextHealth, nextIngestion, nextDetections, nextIncidents, nextCoverage, nextFleet] = await Promise.all([
          fetchSystemHealth(),
          fetchIngestionStatus().catch(() => null),
          fetchDetectionsList({ limit: 6 }),
          getIncidents(50),
          fetchAssetsCoverage().catch(() => null),
          fetchFleetStatus().catch(() => null),
        ]);

        if (cancelled) return;

        setHealth(nextHealth);
        setIngestion(nextIngestion);
        setDetections(nextDetections.detections);
        setIncidents(nextIncidents.incidents);
        setCoverage(nextCoverage as CoveragePayload | null);
        setFleet(nextFleet);
      } catch {
        if (cancelled) return;
        setHealth(null);
        setIngestion(null);
        setDetections([]);
        setIncidents([]);
        setCoverage(null);
        setFleet(null);
      }
    };

    void load();

    return () => {
      cancelled = true;
    };
  }, []);

  const activeIncidents = useMemo(
    () => incidents.filter((row) => !["RESOLVED", "CLOSED"].includes(row.status.toUpperCase())),
    [incidents],
  );
  const registered = coverage?.agents_registered ?? 0;
  const activeAgents = coverage?.agents_active_24h ?? 0;
  const detectionCount = detections.length;
  const onlineFleet = Array.isArray(fleet?.agents)
    ? (fleet.agents as { status?: string }[]).filter((agent) => agent.status?.toUpperCase() === "ONLINE").length
    : 0;
  const pipelineHealthy = ingestion?.pipeline_healthy === true;
  const serviceStable = health?.status === "ok" && !health?.circuit_breaker_tripped && health?.db;
  const recommendedViews = useMemo(() => {
    const nextViews: { title: string; to: string; reason: string }[] = [];

    if (!serviceStable) {
      nextViews.push({
        title: "Operational health",
        to: "/health",
        reason: "Platform continuity needs validation before relying on broader reporting.",
      });
    }
    if (activeIncidents.length > 0) {
      nextViews.push({
        title: "Incidents",
        to: "/incidents",
        reason: `${activeIncidents.length} active incident${activeIncidents.length === 1 ? "" : "s"} require leadership follow-through.`,
      });
    }
    if (registered === 0 || activeAgents < registered) {
      nextViews.push({
        title: "Asset coverage",
        to: "/asset-coverage",
        reason: "Coverage posture is incomplete enough to affect confidence in the current operating picture.",
      });
    }
    if (detectionCount > 0) {
      nextViews.push({
        title: "Detections",
        to: "/detections",
        reason: `${detectionCount} ranked finding${detectionCount === 1 ? "" : "s"} are available for analyst review.`,
      });
    }
    if (nextViews.length === 0) {
      nextViews.push({
        title: "Command center",
        to: "/dashboard",
        reason: "The combined operator view is the best next stop when posture and workload are stable.",
      });
    }

    return nextViews.slice(0, 3);
  }, [activeAgents, activeIncidents.length, detectionCount, registered, serviceStable]);

  const executiveNarrative = useMemo(() => {
    if (!health) return "Platform status is temporarily unavailable. Confirm service connectivity before relying on this briefing.";
    if (!serviceStable) return "Core processing or data services require attention. Resolve platform health before broadening operational commitments.";
    if (activeIncidents.length > 0) return "Platform services are stable, but active incident response remains in progress and should stay under executive watch.";
    if (registered > 0 && activeAgents === 0) return "Core services are healthy, but endpoint coverage is not active enough to support confident operational conclusions.";
    return "Core services, data flow, and analyst queues are stable enough for normal operating cadence.";
  }, [activeAgents, activeIncidents.length, health, registered, serviceStable]);

  return (
    <div className="soc-page">
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Executive summary</h1>
          <p className="soc-page-subtitle">
            Leadership view of service continuity, response activity, and coverage posture. Each summary below maps back
            to the same operational data used by analysts.
          </p>
        </div>
      </header>

      <section className="enterprise-hero">
        <div className="enterprise-hero__content">
          <span className="enterprise-eyebrow">Leadership brief</span>
          <h2 className="enterprise-hero__title">
            {serviceStable ? "Operating posture is stable enough for normal oversight." : "Executive attention is required on platform posture."}
          </h2>
          <p className="enterprise-hero__copy">{executiveNarrative}</p>
        </div>

        <div className="command-scoreboard">
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Service continuity</span>
            <strong className="command-scoreboard__value">{serviceStable ? "Stable" : "At risk"}</strong>
            <span className="command-scoreboard__meta">{health?.db ? "Database reachable" : "Database unavailable"}</span>
          </article>
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Response activity</span>
            <strong className="command-scoreboard__value">{activeIncidents.length}</strong>
            <span className="command-scoreboard__meta">Active incidents requiring follow-through</span>
          </article>
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Coverage</span>
            <strong className="command-scoreboard__value">{registered > 0 ? `${Math.round((activeAgents / registered) * 100)}%` : "0%"}</strong>
            <span className="command-scoreboard__meta">Registered assets active in the last 24 hours</span>
          </article>
        </div>
      </section>

      <section className="command-kpi-grid">
        <article className="command-kpi-card">
          <div className={`command-kpi-card__icon command-kpi-card__icon--${serviceStable ? "ok" : "critical"}`}>
            <BriefcaseBusiness size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Core status</div>
            <div className="command-kpi-card__value">{health?.status?.toUpperCase() ?? "Unavailable"}</div>
            <p className="command-kpi-card__copy">Primary measure of whether security operations can proceed without platform friction.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className={`command-kpi-card__icon command-kpi-card__icon--${pipelineHealthy ? "ok" : "warning"}`}>
            <Waves size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Data flow</div>
            <div className="command-kpi-card__value">{typeof ingestion?.overall_status === "string" ? ingestion.overall_status : "Unknown"}</div>
            <p className="command-kpi-card__copy">Executive view of whether telemetry is reaching the platform and staying processable.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--warning">
            <ShieldAlert size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Findings to monitor</div>
            <div className="command-kpi-card__value">{detectionCount}</div>
            <p className="command-kpi-card__copy">Current findings in the ranked detection set used for analyst review.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <Users size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Endpoints online</div>
            <div className="command-kpi-card__value">{onlineFleet}</div>
            <p className="command-kpi-card__copy">Current online endpoint count visible in the roster.</p>
          </div>
        </article>
      </section>

      <section className="enterprise-grid enterprise-grid--2">
        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Leadership message</span>
              <h2 className="enterprise-panel__title">What this means now</h2>
            </div>
          </div>
          <div className="brief-list">
            <div className="brief-list__item">
              <div className="brief-list__title">Platform readiness</div>
              <div className="brief-list__copy">
                {serviceStable
                  ? "Core processing, committed writes, and service reachability are all within acceptable limits."
                  : "Core platform health is not fully stable. Executive confidence should remain guarded until operational health is restored."}
              </div>
            </div>
            <div className="brief-list__item">
              <div className="brief-list__title">Response posture</div>
              <div className="brief-list__copy">
                {activeIncidents.length === 0
                  ? "There is no open incident backlog requiring executive intervention."
                  : `${activeIncidents.length} active incident${activeIncidents.length === 1 ? "" : "s"} remain in response workflow and should stay under leadership watch.`}
              </div>
            </div>
            <div className="brief-list__item">
              <div className="brief-list__title">Coverage confidence</div>
              <div className="brief-list__copy">
                {registered === 0
                  ? "Managed coverage has not been established yet."
                  : `${activeAgents} of ${registered} registered assets reported recently, which is the current basis for coverage confidence.`}
              </div>
            </div>
          </div>
        </article>

        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Recommended next view</span>
              <h2 className="enterprise-panel__title">Leadership drill paths</h2>
            </div>
          </div>
          <div className="priority-rail">
            {recommendedViews.map((view) => (
              <div key={view.to} className="priority-rail__item">
                <div className="priority-rail__icon">
                  <ArrowUpRight size={16} aria-hidden />
                </div>
                <div>
                  <div className="priority-rail__title">
                    <Link to={view.to} className="enterprise-panel__link">
                      {view.title}
                    </Link>
                  </div>
                  <div className="priority-rail__copy">{view.reason}</div>
                </div>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="enterprise-panel">
        <div className="enterprise-panel__header">
          <div>
            <span className="enterprise-eyebrow">Current observations</span>
            <h2 className="enterprise-panel__title">Leadership watch items</h2>
          </div>
        </div>
        <div className="table-shell">
          <table className="soc-table soc-table--enterprise">
            <thead>
              <tr>
                <th className="soc-th">Watch item</th>
                <th className="soc-th">Current state</th>
                <th className="soc-th">Why it matters</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="soc-td">Core processing</td>
                <td className="soc-td">{serviceStable ? "Stable" : "Needs attention"}</td>
                <td className="soc-td">Platform instability reduces confidence in downstream analyst and executive reporting.</td>
              </tr>
              <tr>
                <td className="soc-td">Incident workload</td>
                <td className="soc-td">{activeIncidents.length === 0 ? "No active backlog" : `${activeIncidents.length} active incident${activeIncidents.length === 1 ? "" : "s"}`}</td>
                <td className="soc-td">Open response work is the clearest indicator of active operational disruption.</td>
              </tr>
              <tr>
                <td className="soc-td">Coverage confidence</td>
                <td className="soc-td">{registered > 0 ? `${activeAgents}/${registered} active in 24h` : "No registered coverage"}</td>
                <td className="soc-td">Incomplete coverage reduces confidence that the current picture reflects the full environment.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
