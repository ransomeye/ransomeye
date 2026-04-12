import { useEffect, useMemo, useState } from "react";
import { Activity, CheckCircle2, Database, Radar, Shield, ShieldAlert } from "lucide-react";
import {
  fetchFleetStatus,
  fetchIngestionStatus,
  fetchShadowIntelStatus,
  fetchSystemHealth,
  type HealthResponse,
} from "../lib/client";
import { useTelemetryStream } from "../hooks/useTelemetryStream";

type FleetAgent = {
  agent_id?: string;
  hostname?: string;
  status?: string;
  last_heartbeat?: string;
};

function healthTone(health: HealthResponse | null): "healthy" | "degraded" {
  if (!health) return "degraded";
  return health.circuit_breaker_tripped || health.status !== "ok" || !health.db ? "degraded" : "healthy";
}

export function SystemHealth() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [ingestion, setIngestion] = useState<Record<string, unknown> | null>(null);
  const [fleet, setFleet] = useState<FleetAgent[]>([]);
  const [shadow, setShadow] = useState<Record<string, unknown> | null>(null);
  const [loadErr, setLoadErr] = useState(false);
  const { connected } = useTelemetryStream({ maxRows: 1 });

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const [nextHealth, nextIngestion, nextFleet, nextShadow] = await Promise.all([
          fetchSystemHealth(),
          fetchIngestionStatus().catch(() => null),
          fetchFleetStatus().catch(() => null),
          fetchShadowIntelStatus().catch(() => null),
        ]);

        if (cancelled) return;

        setHealth(nextHealth);
        setIngestion(nextIngestion);
        setFleet((nextFleet?.agents as FleetAgent[] | undefined) ?? []);
        setShadow(nextShadow);
        setLoadErr(false);
      } catch {
        if (cancelled) return;
        setHealth(null);
        setIngestion(null);
        setFleet([]);
        setShadow(null);
        setLoadErr(true);
      }
    };

    void load();

    return () => {
      cancelled = true;
    };
  }, []);

  const tone = healthTone(health);
  const onlineAgents = fleet.filter((agent) => agent.status?.toUpperCase() === "ONLINE").length;
  const offlineAgents = fleet.filter((agent) => agent.status?.toUpperCase() !== "ONLINE").length;
  const pipelineHealthy = ingestion?.pipeline_healthy === true;
  const ingestionOverall = typeof ingestion?.overall_status === "string" ? ingestion.overall_status : "Unknown";
  const advisoryReady = shadow?.status === "ok" && shadow?.authoritative === false;

  const firstTenSeconds = useMemo(() => {
    if (!health) return "Platform health data is unavailable. Confirm core service reachability before relying on this console.";
    if (tone === "healthy" && pipelineHealthy) return "Core processing and data flow are stable. Review endpoint coverage and analyst queues next.";
    if (!health.db) return "Database reachability is impaired. Restore data services before trusting downstream status.";
    if (health.circuit_breaker_tripped) return "Protective controls are active. Review backlog, sync latency, and upstream pressure immediately.";
    return "Some platform indicators need review. Validate data flow and reporting endpoints before analyst load increases.";
  }, [health, pipelineHealthy, tone]);

  return (
    <div className="soc-page">
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Operational health</h1>
          <p className="soc-page-subtitle">
            Use this page to confirm service continuity, data flow, and endpoint reporting posture before escalating
            analyst or executive concerns.
          </p>
        </div>
        <div className="soc-page-header__meta">
          <span className={`soc-live-pill ${connected ? "soc-live-pill--on" : "soc-live-pill--off"}`}>
            <span className="soc-live-pill__dot" aria-hidden />
            {connected ? "Telemetry stream connected" : "Telemetry stream unavailable"}
          </span>
        </div>
      </header>

      <section className={`enterprise-hero enterprise-hero--${tone}`}>
        <div className="enterprise-hero__content">
          <span className="enterprise-eyebrow">Operational posture</span>
          <h2 className="enterprise-hero__title">
            {tone === "healthy" ? "Core services are operating within expected limits." : "Platform posture needs attention."}
          </h2>
          <p className="enterprise-hero__copy">{firstTenSeconds}</p>
        </div>
        <div className="command-scoreboard">
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Core status</span>
            <strong className="command-scoreboard__value">{health?.status?.toUpperCase() ?? "Unavailable"}</strong>
            <span className="command-scoreboard__meta">{health?.db ? "Database reachable" : "Database not reachable"}</span>
          </article>
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Data flow</span>
            <strong className="command-scoreboard__value">{ingestionOverall}</strong>
            <span className="command-scoreboard__meta">{pipelineHealthy ? "Pipeline healthy" : "Pipeline needs review"}</span>
          </article>
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Reporting endpoints</span>
            <strong className="command-scoreboard__value">{onlineAgents}</strong>
            <span className="command-scoreboard__meta">
              {offlineAgents > 0 ? `${offlineAgents} endpoint${offlineAgents === 1 ? "" : "s"} offline` : "No offline endpoints in current roster"}
            </span>
          </article>
        </div>
      </section>

      {loadErr && (
        <div className="enterprise-inline-error" role="alert">
          Health endpoints are unavailable. Confirm service connectivity and refresh this view.
        </div>
      )}

      <section className="command-kpi-grid">
        <article className="command-kpi-card">
          <div className={`command-kpi-card__icon command-kpi-card__icon--${tone === "healthy" ? "ok" : "critical"}`}>
            <Shield size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Storage sync latency</div>
            <div className="command-kpi-card__value">{health ? `${health.wal_fsync_latency_ms.toFixed(3)} ms` : "Unavailable"}</div>
            <p className="command-kpi-card__copy">Low latency indicates that committed writes are keeping pace with demand.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <Activity size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Queue depth</div>
            <div className="command-kpi-card__value">{health?.event_queue_depth ?? "Unavailable"}</div>
            <p className="command-kpi-card__copy">Backlog should remain low during normal operating conditions.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className={`command-kpi-card__icon command-kpi-card__icon--${health?.db ? "ok" : "critical"}`}>
            <Database size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Database reachability</div>
            <div className="command-kpi-card__value">{health?.db ? "Connected" : "Unavailable"}</div>
            <p className="command-kpi-card__copy">This directly affects committed evidence, reporting, and replay validation.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className={`command-kpi-card__icon command-kpi-card__icon--${advisoryReady ? "neutral" : "warning"}`}>
            <Radar size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Advisory plane</div>
            <div className="command-kpi-card__value">{advisoryReady ? "Available" : "Not active"}</div>
            <p className="command-kpi-card__copy">Advisory analysis is isolated from enforcement and committed evidence.</p>
          </div>
        </article>
      </section>

      <section className="enterprise-grid enterprise-grid--3">
        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Core engine</span>
              <h2 className="enterprise-panel__title">Service readiness</h2>
            </div>
          </div>
          <dl className="detail-list">
            <div>
              <dt>Overall status</dt>
              <dd>{health?.status?.toUpperCase() ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Batch size</dt>
              <dd>{health?.batch_size ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Circuit breaker</dt>
              <dd>{health?.circuit_breaker_tripped ? "Protective isolation active" : "Normal"}</dd>
            </div>
          </dl>
        </article>

        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Data flow</span>
              <h2 className="enterprise-panel__title">Pipeline posture</h2>
            </div>
          </div>
          <dl className="detail-list">
            <div>
              <dt>Overall state</dt>
              <dd>{ingestionOverall}</dd>
            </div>
            <div>
              <dt>Pipeline health</dt>
              <dd>{pipelineHealthy ? "Healthy" : "Needs review"}</dd>
            </div>
            <div>
              <dt>Transport</dt>
              <dd>{health?.transport ?? "Unavailable"}</dd>
            </div>
          </dl>
        </article>

        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Sensor posture</span>
              <h2 className="enterprise-panel__title">Endpoint reporting</h2>
            </div>
          </div>
          {fleet.length === 0 ? (
            <div className="enterprise-empty enterprise-empty--compact">
              <h3>No endpoint roster available</h3>
              <p>Endpoint health will appear here when collectors and heartbeat data are available.</p>
            </div>
          ) : (
            <div className="roster-list">
              {fleet.slice(0, 5).map((agent) => (
                <div key={agent.agent_id ?? agent.hostname} className="roster-list__item">
                  <div>
                    <div className="roster-list__name">{agent.hostname || agent.agent_id || "Unknown endpoint"}</div>
                    <div className="roster-list__meta">{agent.last_heartbeat ? new Date(agent.last_heartbeat).toLocaleString() : "No heartbeat recorded"}</div>
                  </div>
                  <div className={`status-dot status-dot--${agent.status?.toUpperCase() === "ONLINE" ? "healthy" : "degraded"}`}>
                    {agent.status ?? "Unknown"}
                  </div>
                </div>
              ))}
            </div>
          )}
        </article>
      </section>

      <section className="enterprise-panel">
        <div className="enterprise-panel__header">
          <div>
            <span className="enterprise-eyebrow">What to do next</span>
            <h2 className="enterprise-panel__title">Operational guidance</h2>
          </div>
        </div>
        <div className="priority-rail">
          <div className="priority-rail__item">
            <div className="priority-rail__icon">
              {tone === "healthy" ? <CheckCircle2 size={16} aria-hidden /> : <ShieldAlert size={16} aria-hidden />}
            </div>
            <div>
              <div className="priority-rail__title">Confirm service continuity</div>
              <div className="priority-rail__copy">
                If database reachability or circuit state is degraded, resolve that first. Analyst views depend on these
                systems staying healthy.
              </div>
            </div>
          </div>
          <div className="priority-rail__item">
            <div className="priority-rail__icon">
              <Activity size={16} aria-hidden />
            </div>
            <div>
              <div className="priority-rail__title">Review data flow</div>
              <div className="priority-rail__copy">
                Use the data flow view when overall ingestion or pipeline health drops below normal operating posture.
              </div>
            </div>
          </div>
          <div className="priority-rail__item">
            <div className="priority-rail__icon">
              <Radar size={16} aria-hidden />
            </div>
            <div>
              <div className="priority-rail__title">Close visibility gaps</div>
              <div className="priority-rail__copy">
                Offline endpoints reduce confidence in command and executive views. Re-establish coverage before drawing
                broader conclusions.
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
