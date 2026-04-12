import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Activity, Database, ShieldAlert, Users } from "lucide-react";
import { fetchFleetStatus } from "../lib/client";

type FleetAgent = {
  agent_id?: string;
  hostname?: string;
  status?: string;
  last_heartbeat?: string;
};

type FleetPayload = {
  agents?: FleetAgent[];
  core?: {
    events_dropped?: number;
    events_ingested?: number;
    queue_drops?: number;
  };
  dpi_probe?: {
    plane?: string;
    metrics_scope?: string;
  };
  sine_plane?: string;
};

export function Fleet() {
  const [data, setData] = useState<FleetPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchFleetStatus()
      .then((d) => {
        setData(d as FleetPayload);
        setError(null);
      })
      .catch((loadError: Error) => {
        setData(null);
        setError(loadError.message);
      });
  }, []);

  const agents = data?.agents ?? [];
  const onlineAgents = useMemo(
    () => agents.filter((agent) => agent.status?.toUpperCase() === "ONLINE").length,
    [agents],
  );
  const offlineAgents = agents.length - onlineAgents;
  const lastSeen = agents
    .map((agent) => agent.last_heartbeat)
    .filter((value): value is string => typeof value === "string" && value.length > 0)
    .sort()
    .at(-1);

  return (
    <div className="soc-page">
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Endpoint roster</h1>
          <p className="soc-page-subtitle">
            Review enrolled endpoints, heartbeat posture, and the collector-side counts currently available to the
            console. This view is backed by the fleet status route only.
          </p>
        </div>
      </header>

      <section className="enterprise-hero">
        <div className="enterprise-hero__content">
          <span className="enterprise-eyebrow">Roster posture</span>
          <h2 className="enterprise-hero__title">
            {agents.length === 0
              ? "No enrolled endpoints are currently visible."
              : offlineAgents > 0
                ? "Some enrolled endpoints are not currently reporting."
                : "All visible endpoints are currently reporting as online."}
          </h2>
          <p className="enterprise-hero__copy">
            Endpoint status on this page comes from heartbeat and fleet status data. Use asset coverage and data flow
            views for broader reporting confidence.
          </p>
          <div className="enterprise-hero__actions">
            <Link to="/asset-coverage" className="enterprise-btn enterprise-btn--primary">
              Open asset coverage
            </Link>
            <Link to="/ingestion" className="enterprise-btn enterprise-btn--secondary">
              Review data flow
            </Link>
          </div>
        </div>
        <div className="command-scoreboard">
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Visible endpoints</span>
            <strong className="command-scoreboard__value">{agents.length}</strong>
            <span className="command-scoreboard__meta">Records returned by fleet status</span>
          </article>
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Online now</span>
            <strong className="command-scoreboard__value">{onlineAgents}</strong>
            <span className="command-scoreboard__meta">{offlineAgents > 0 ? `${offlineAgents} offline` : "No offline endpoints returned"}</span>
          </article>
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Last heartbeat seen</span>
            <strong className="command-scoreboard__value">{lastSeen ? new Date(lastSeen).toLocaleTimeString() : "None"}</strong>
            <span className="command-scoreboard__meta">{lastSeen ? new Date(lastSeen).toLocaleDateString() : "No heartbeat data available"}</span>
          </article>
        </div>
      </section>

      {error && (
        <div className="enterprise-inline-error" role="alert">
          {error}
        </div>
      )}

      <section className="command-kpi-grid">
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <Users size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Roster size</div>
            <div className="command-kpi-card__value">{agents.length}</div>
            <p className="command-kpi-card__copy">Endpoints returned by the live fleet status route.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className={`command-kpi-card__icon command-kpi-card__icon--${offlineAgents > 0 ? "warning" : "ok"}`}>
            <ShieldAlert size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Offline endpoints</div>
            <div className="command-kpi-card__value">{offlineAgents}</div>
            <p className="command-kpi-card__copy">Endpoints not currently reporting as online.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <Activity size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Events ingested</div>
            <div className="command-kpi-card__value">{data?.core?.events_ingested ?? 0}</div>
            <p className="command-kpi-card__copy">Collector-side ingest count exposed by the current fleet payload.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--warning">
            <Database size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Dropped or queued out</div>
            <div className="command-kpi-card__value">{(data?.core?.events_dropped ?? 0) + (data?.core?.queue_drops ?? 0)}</div>
            <p className="command-kpi-card__copy">Combined dropped and queue-drop count currently published by fleet status.</p>
          </div>
        </article>
      </section>

      <section className="enterprise-grid enterprise-grid--2">
        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Endpoint records</span>
              <h2 className="enterprise-panel__title">Current roster</h2>
            </div>
          </div>
          {agents.length === 0 ? (
            <div className="enterprise-empty">
              <h3>No endpoints are reporting</h3>
              <p>Verify enrollment and heartbeat collection before relying on endpoint posture.</p>
            </div>
          ) : (
            <div className="roster-list">
              {agents.map((agent) => (
                <div key={agent.agent_id ?? agent.hostname} className="roster-list__item">
                  <div>
                    <div className="roster-list__name">{agent.hostname || agent.agent_id || "Unknown endpoint"}</div>
                    <div className="roster-list__meta">
                      {agent.last_heartbeat ? new Date(agent.last_heartbeat).toLocaleString() : "No heartbeat recorded"}
                    </div>
                  </div>
                  <div className={`status-dot status-dot--${agent.status?.toUpperCase() === "ONLINE" ? "healthy" : "degraded"}`}>
                    {agent.status ?? "Unknown"}
                  </div>
                </div>
              ))}
            </div>
          )}
        </article>

        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">What the backend exposes</span>
              <h2 className="enterprise-panel__title">Available runtime posture</h2>
            </div>
          </div>
          <dl className="detail-list">
            <div>
              <dt>Signal plane</dt>
              <dd>{data?.sine_plane ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>DPI plane</dt>
              <dd>{data?.dpi_probe?.plane ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>DPI metrics scope</dt>
              <dd>{data?.dpi_probe?.metrics_scope ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Not yet available here</dt>
              <dd>Per-endpoint historical trends, enrollment workflow, and case-linked endpoint evidence are not exposed by this route.</dd>
            </div>
          </dl>
        </article>
      </section>
    </div>
  );
}
