import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Database,
  Radar,
  ShieldAlert,
  Users,
} from "lucide-react";
import {
  fetchDetectionsList,
  fetchFleetStatus,
  fetchIngestionStatus,
  fetchSystemHealth,
  getAlerts,
  getIncidents,
  type DetectionRow,
  type HealthResponse,
  type IncidentRow,
} from "../lib/client";
import { useTelemetryStream } from "../hooks/useTelemetryStream";
import { Alerts } from "../components/Alerts";
import { IncidentsPanel } from "../components/IncidentsPanel";

type FleetAgent = {
  agent_id?: string;
  hostname?: string;
  status?: string;
  last_heartbeat?: string;
};

function formatPercent(value: number): string {
  return `${(value * 100).toFixed(0)}%`;
}

function formatTimestamp(value?: string): string {
  if (!value) return "No recent activity";
  return new Date(value).toLocaleString();
}

function topSignalSummary(signals: Record<string, unknown>): string {
  const ranked = Object.entries(signals)
    .filter(([, value]) => typeof value === "number")
    .sort(([, a], [, b]) => Number(b) - Number(a))
    .slice(0, 2);

  if (ranked.length === 0) return "No primary contributing signals recorded";
  return ranked.map(([key, value]) => `${key.replaceAll("_", " ")} ${Number(value).toFixed(2)}`).join(" · ");
}

function detectionTone(row: DetectionRow): "critical" | "warning" | "stable" {
  if (row.posterior >= 0.85 || row.aec_class_index >= 3) return "critical";
  if (row.posterior >= 0.6 || row.aec_class_index >= 2) return "warning";
  return "stable";
}

function incidentLabel(incidents: IncidentRow[]): string {
  const active = incidents.filter((row) => !["RESOLVED", "CLOSED"].includes(row.status.toUpperCase())).length;
  return active === 0 ? "No active incidents" : `${active} active incident${active === 1 ? "" : "s"}`;
}

export function Dashboard() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [detections, setDetections] = useState<DetectionRow[]>([]);
  const [alertsTotal, setAlertsTotal] = useState(0);
  const [incidents, setIncidents] = useState<IncidentRow[]>([]);
  const [fleetAgents, setFleetAgents] = useState<FleetAgent[]>([]);
  const [ingestionStatus, setIngestionStatus] = useState<Record<string, unknown> | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "error">("loading");
  const [incReload, setIncReload] = useState(0);
  const { rows: liveTelemetry, connected, historyAvailable } = useTelemetryStream({ maxRows: 12 });

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      setLoadState("loading");
      try {
        const [nextHealth, nextDetections, nextAlerts, nextIncidents, nextFleet, nextIngestion] = await Promise.all([
          fetchSystemHealth(),
          fetchDetectionsList({ limit: 8 }),
          getAlerts(50),
          getIncidents(50),
          fetchFleetStatus().catch(() => null),
          fetchIngestionStatus().catch(() => null),
        ]);

        if (cancelled) return;

        setHealth(nextHealth);
        setDetections(nextDetections.detections);
        setAlertsTotal(nextAlerts.total);
        setIncidents(nextIncidents.incidents);
        setFleetAgents(((nextFleet?.agents as FleetAgent[] | undefined) ?? []).slice(0, 6));
        setIngestionStatus(nextIngestion);
        setLoadState("ready");
      } catch {
        if (cancelled) return;
        setHealth(null);
        setDetections([]);
        setAlertsTotal(0);
        setIncidents([]);
        setFleetAgents([]);
        setIngestionStatus(null);
        setLoadState("error");
      }
    };

    void load();

    return () => {
      cancelled = true;
    };
  }, [incReload]);

  const topDetections = useMemo(() => {
    return [...detections].sort((a, b) => b.posterior - a.posterior);
  }, [detections]);

  const activeIncidents = incidents.filter((row) => !["RESOLVED", "CLOSED"].includes(row.status.toUpperCase()));
  const onlineAgents = fleetAgents.filter((row) => row.status?.toUpperCase() === "ONLINE").length;
  const offlineAgents = fleetAgents.filter((row) => row.status?.toUpperCase() !== "ONLINE").length;
  const ingestionOverall = typeof ingestionStatus?.overall_status === "string" ? ingestionStatus.overall_status : "Unknown";
  const pipelineHealthy = ingestionStatus?.pipeline_healthy === true;
  const queueDepth = health?.event_queue_depth ?? 0;
  const latestEvent = liveTelemetry[0];

  return (
    <div className="soc-page soc-page--command">
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Command center</h1>
          <p className="soc-page-subtitle">
            Start here to understand service continuity, analyst workload, sensor posture, and the next queue that
            needs attention.
          </p>
        </div>
        <div className="soc-page-header__meta">
          <span className={`soc-live-pill ${connected ? "soc-live-pill--on" : "soc-live-pill--off"}`}>
            <span className="soc-live-pill__dot" aria-hidden />
            {connected ? "Telemetry stream connected" : "Telemetry stream unavailable"}
          </span>
          {loadState === "error" && (
            <span className="soc-inline-warn" role="alert">
              Command data could not be refreshed. Check service connectivity.
            </span>
          )}
        </div>
      </header>

      <section className="enterprise-hero">
        <div className="enterprise-hero__content">
          <span className="enterprise-eyebrow">Current operating picture</span>
          <h2 className="enterprise-hero__title">
            {health?.status === "ok" && !health?.circuit_breaker_tripped
              ? "Core services are stable and ready for investigation work."
              : "Operational posture needs attention before analyst load increases."}
          </h2>
          <p className="enterprise-hero__copy">
            Use the ranked queues below to decide whether to escalate findings, clear analyst backlog, or restore sensor
            and platform health first.
          </p>
          <div className="enterprise-hero__actions">
            <Link to="/alerts" className="enterprise-btn enterprise-btn--primary">
              Review alert queue
            </Link>
            <Link to="/health" className="enterprise-btn enterprise-btn--secondary">
              Check operational health
            </Link>
          </div>
        </div>

        <div className="command-scoreboard" aria-label="Command center summary">
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Service continuity</span>
            <strong className="command-scoreboard__value">
              {health?.status === "ok" && !health?.circuit_breaker_tripped ? "Stable" : "Review required"}
            </strong>
            <span className="command-scoreboard__meta">
              {health ? `Storage sync ${health.wal_fsync_latency_ms.toFixed(3)} ms` : "Health data unavailable"}
            </span>
          </article>
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Escalation queue</span>
            <strong className="command-scoreboard__value">{alertsTotal}</strong>
            <span className="command-scoreboard__meta">{incidentLabel(incidents)}</span>
          </article>
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Sensor posture</span>
            <strong className="command-scoreboard__value">{onlineAgents}</strong>
            <span className="command-scoreboard__meta">
              {offlineAgents > 0 ? `${offlineAgents} endpoint${offlineAgents === 1 ? "" : "s"} offline` : "No offline endpoints in current roster"}
            </span>
          </article>
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Data flow</span>
            <strong className="command-scoreboard__value">{ingestionOverall}</strong>
            <span className="command-scoreboard__meta">{pipelineHealthy ? "Pipeline healthy" : "Pipeline needs review"}</span>
          </article>
        </div>
      </section>

      <section className="command-kpi-grid" aria-label="Priority indicators">
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--critical">
            <AlertTriangle size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Alerts waiting</div>
            <div className="command-kpi-card__value">{alertsTotal}</div>
            <p className="command-kpi-card__copy">
              {alertsTotal === 0
                ? "No elevated findings are waiting for escalation."
                : "Elevated findings are ready for analyst triage."}
            </p>
          </div>
        </article>

        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--warning">
            <ShieldAlert size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Active incidents</div>
            <div className="command-kpi-card__value">{activeIncidents.length}</div>
            <p className="command-kpi-card__copy">
              {activeIncidents.length === 0
                ? "No incidents currently require coordinated response."
                : "Response owners should confirm containment and resolution next steps."}
            </p>
          </div>
        </article>

        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <Users size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Reporting endpoints</div>
            <div className="command-kpi-card__value">{onlineAgents}</div>
            <p className="command-kpi-card__copy">
              {fleetAgents.length === 0 ? "Endpoint roster is not reporting to the console." : "Current roster contributing heartbeat data."}
            </p>
          </div>
        </article>

        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <Database size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Processing backlog</div>
            <div className="command-kpi-card__value">{queueDepth.toLocaleString()}</div>
            <p className="command-kpi-card__copy">
              {queueDepth === 0 ? "No backlog is building in the processing queue." : "Analysts should watch for delayed ingestion or storage pressure."}
            </p>
          </div>
        </article>
      </section>

      <section className="enterprise-grid enterprise-grid--2" aria-label="Immediate attention">
        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">First ten seconds</span>
              <h2 className="enterprise-panel__title">What needs attention now</h2>
            </div>
            <Link to="/detections" className="enterprise-panel__link">
              Open detection workflow
            </Link>
          </div>

          <div className="priority-rail">
            <div className="priority-rail__item">
              <div className="priority-rail__icon">
                {alertsTotal > 0 ? <AlertTriangle size={16} aria-hidden /> : <CheckCircle2 size={16} aria-hidden />}
              </div>
              <div>
                <div className="priority-rail__title">{alertsTotal > 0 ? "Alert queue requires triage" : "Alert queue is clear"}</div>
                <div className="priority-rail__copy">
                  {alertsTotal > 0
                    ? "Review elevated findings first to decide whether they should become analyst-owned incidents."
                    : "No queued alerts need immediate escalation. Continue with detection review and posture validation."}
                </div>
              </div>
            </div>

            <div className="priority-rail__item">
              <div className="priority-rail__icon">
                {activeIncidents.length > 0 ? <Clock3 size={16} aria-hidden /> : <CheckCircle2 size={16} aria-hidden />}
              </div>
              <div>
                <div className="priority-rail__title">{activeIncidents.length > 0 ? "Incident owners need follow-through" : "No coordinated response is open"}</div>
                <div className="priority-rail__copy">
                  {activeIncidents.length > 0
                    ? "Confirm current status, ownership, and containment progress before opening new work."
                    : "The response queue is not blocking new triage at the moment."}
                </div>
              </div>
            </div>

            <div className="priority-rail__item">
              <div className="priority-rail__icon">
                {offlineAgents > 0 ? <Radar size={16} aria-hidden /> : <CheckCircle2 size={16} aria-hidden />}
              </div>
              <div>
                <div className="priority-rail__title">{offlineAgents > 0 ? "Coverage is incomplete" : "Coverage is steady"}</div>
                <div className="priority-rail__copy">
                  {offlineAgents > 0
                    ? "Offline endpoints reduce visibility and should be reviewed alongside command workload."
                    : "Current roster is not showing additional endpoint outages."}
                </div>
              </div>
            </div>
          </div>
        </article>

        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Analyst watchlist</span>
              <h2 className="enterprise-panel__title">Highest-priority detections</h2>
            </div>
            <Link to="/detections" className="enterprise-panel__link">
              View all detections
            </Link>
          </div>

          {topDetections.length === 0 ? (
            <div className="enterprise-empty">
              <h3>No detections are waiting for analyst review</h3>
              <p>
                When detections arrive, this watchlist will surface the strongest signals first and point analysts to the
                next workflow.
              </p>
            </div>
          ) : (
            <div className="watchlist-table">
              {topDetections.map((row) => (
                <article key={row.id} className={`watchlist-row watchlist-row--${detectionTone(row)}`}>
                  <div className="watchlist-row__meta">
                    <span className="watchlist-row__confidence">{formatPercent(row.posterior)}</span>
                    <span className="watchlist-row__badge">{row.aec_class}</span>
                  </div>
                  <div className="watchlist-row__body">
                    <div className="watchlist-row__title">{row.agent_id || "Unattributed endpoint"}</div>
                    <div className="watchlist-row__copy">{topSignalSummary(row.signals)}</div>
                  </div>
                  <div className="watchlist-row__time">{formatTimestamp(row.timestamp)}</div>
                </article>
              ))}
            </div>
          )}
        </article>
      </section>

      <section className="enterprise-grid enterprise-grid--2" aria-label="Response workflow">
        <div className="enterprise-panel">
          <Alerts embedded onIncidentCreated={() => setIncReload((value) => value + 1)} />
        </div>
        <div className="enterprise-panel">
          <IncidentsPanel embedded reloadToken={incReload} />
        </div>
      </section>

      <section className="enterprise-grid enterprise-grid--3" aria-label="Operational posture">
        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Platform posture</span>
              <h2 className="enterprise-panel__title">Core processing</h2>
            </div>
          </div>
          <dl className="detail-list">
            <div>
              <dt>Health status</dt>
              <dd>{health?.status?.toUpperCase() ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Storage sync latency</dt>
              <dd>{health ? `${health.wal_fsync_latency_ms.toFixed(3)} ms` : "Unavailable"}</dd>
            </div>
            <div>
              <dt>Circuit state</dt>
              <dd>{health?.circuit_breaker_tripped ? "Protective isolation active" : "Within normal limits"}</dd>
            </div>
          </dl>
        </article>

        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Data flow</span>
              <h2 className="enterprise-panel__title">Ingestion posture</h2>
            </div>
            <Link to="/ingestion" className="enterprise-panel__link">
              Open data flow
            </Link>
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
              <dt>Latest live event</dt>
              <dd>
                {latestEvent
                  ? latestEvent.event_type
                  : connected
                    ? "Awaiting live stream sample"
                    : historyAvailable
                      ? "No recent telemetry sample"
                      : "Historical stream unavailable"}
              </dd>
            </div>
          </dl>
        </article>

        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Endpoint posture</span>
              <h2 className="enterprise-panel__title">Reporting roster</h2>
            </div>
            <Link to="/asset-coverage" className="enterprise-panel__link">
              View coverage
            </Link>
          </div>
          {fleetAgents.length === 0 ? (
            <div className="enterprise-empty enterprise-empty--compact">
              <h3>No roster data available</h3>
              <p>Confirm enrollment and heartbeat collection to restore endpoint posture visibility.</p>
            </div>
          ) : (
            <div className="roster-list">
              {fleetAgents.map((agent) => (
                <div key={agent.agent_id ?? agent.hostname} className="roster-list__item">
                  <div>
                    <div className="roster-list__name">{agent.hostname || agent.agent_id || "Unknown endpoint"}</div>
                    <div className="roster-list__meta">{agent.agent_id ?? "Unidentified agent"}</div>
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
    </div>
  );
}
