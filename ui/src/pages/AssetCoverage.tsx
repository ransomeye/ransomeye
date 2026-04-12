import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Radar, ShieldCheck, TriangleAlert, Users } from "lucide-react";
import { fetchAssetsCoverage, fetchFleetStatus } from "../lib/client";

type CoveragePayload = {
  agents_registered?: number;
  agents_active_24h?: number;
  distinct_emitters_24h?: number;
  telemetry_sources_24h?: { source?: string; events?: number }[];
};

type FleetAgent = {
  agent_id?: string;
  hostname?: string;
  status?: string;
  last_heartbeat?: string;
};

export function AssetCoverage() {
  const [coverage, setCoverage] = useState<CoveragePayload | null>(null);
  const [fleetAgents, setFleetAgents] = useState<FleetAgent[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const [nextCoverage, nextFleet] = await Promise.all([
          fetchAssetsCoverage(),
          fetchFleetStatus().catch(() => null),
        ]);

        if (cancelled) return;

        setCoverage(nextCoverage as CoveragePayload);
        setFleetAgents((nextFleet?.agents as FleetAgent[] | undefined) ?? []);
        setErr(null);
      } catch (error) {
        if (cancelled) return;
        setCoverage(null);
        setFleetAgents([]);
        setErr(error instanceof Error ? error.message : "Unable to load asset coverage");
      }
    };

    void load();

    return () => {
      cancelled = true;
    };
  }, []);

  const registered = coverage?.agents_registered ?? 0;
  const active = coverage?.agents_active_24h ?? 0;
  const emitters = coverage?.distinct_emitters_24h ?? 0;
  const sourceRows = coverage?.telemetry_sources_24h ?? [];
  const offlineCount = useMemo(
    () => fleetAgents.filter((agent) => agent.status?.toUpperCase() !== "ONLINE").length,
    [fleetAgents],
  );
  const activeCoverageRate = registered > 0 ? Math.round((active / registered) * 100) : 0;

  return (
    <div className="soc-page">
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Asset coverage</h1>
          <p className="soc-page-subtitle">
            Measure how much of the environment is actively reporting, where telemetry is arriving from, and whether
            endpoint visibility is strong enough for reliable analyst and executive reporting.
          </p>
        </div>
      </header>

      <section className="enterprise-hero">
        <div className="enterprise-hero__content">
          <span className="enterprise-eyebrow">Coverage posture</span>
          <h2 className="enterprise-hero__title">
            {registered === 0
              ? "No managed coverage is currently reporting into the console."
              : active === 0
                ? "Managed assets are registered, but no endpoints have reported recently."
                : "Coverage visibility is established and ready for posture review."}
          </h2>
          <p className="enterprise-hero__copy">
            Asset coverage should be read as an operational visibility view. Use endpoint roster and data flow pages to
            close reporting gaps or validate missing sources.
          </p>
          <div className="enterprise-hero__actions">
            <Link to="/fleet" className="enterprise-btn enterprise-btn--primary">
              Open endpoint roster
            </Link>
            <Link to="/ingestion" className="enterprise-btn enterprise-btn--secondary">
              Review data flow
            </Link>
          </div>
        </div>

        <div className="command-scoreboard">
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Registered assets</span>
            <strong className="command-scoreboard__value">{registered}</strong>
            <span className="command-scoreboard__meta">Known reporting endpoints</span>
          </article>
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Active in 24h</span>
            <strong className="command-scoreboard__value">{active}</strong>
            <span className="command-scoreboard__meta">{registered > 0 ? `${activeCoverageRate}% active coverage` : "No baseline available"}</span>
          </article>
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Distinct emitters</span>
            <strong className="command-scoreboard__value">{emitters}</strong>
            <span className="command-scoreboard__meta">Telemetry identities seen in the last 24 hours</span>
          </article>
        </div>
      </section>

      {err && (
        <div className="enterprise-inline-error" role="alert">
          {err}
        </div>
      )}

      <section className="command-kpi-grid">
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--ok">
            <ShieldCheck size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Coverage rate</div>
            <div className="command-kpi-card__value">{registered > 0 ? `${activeCoverageRate}%` : "0%"}</div>
            <p className="command-kpi-card__copy">Share of registered assets that produced recent telemetry.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className={`command-kpi-card__icon command-kpi-card__icon--${offlineCount > 0 ? "warning" : "ok"}`}>
            <TriangleAlert size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Offline endpoints</div>
            <div className="command-kpi-card__value">{offlineCount}</div>
            <p className="command-kpi-card__copy">Endpoints present in the roster but not currently reporting as online.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <Radar size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Telemetry sources</div>
            <div className="command-kpi-card__value">{sourceRows.length}</div>
            <p className="command-kpi-card__copy">Distinct source families contributing telemetry during the current window.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <Users size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Roster size</div>
            <div className="command-kpi-card__value">{fleetAgents.length}</div>
            <p className="command-kpi-card__copy">Endpoints currently visible in the endpoint roster.</p>
          </div>
        </article>
      </section>

      <section className="enterprise-grid enterprise-grid--2">
        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Source mix</span>
              <h2 className="enterprise-panel__title">Telemetry by source</h2>
            </div>
          </div>
          {sourceRows.length === 0 ? (
            <div className="enterprise-empty">
              <h3>No telemetry sources reported in the current window</h3>
              <p>Validate collectors, endpoint connectivity, and data flow before relying on coverage-driven reporting.</p>
            </div>
          ) : (
            <div className="source-bars">
              {sourceRows.map((row, index) => (
                <div key={`${row.source}-${index}`} className="source-bars__row">
                  <div className="source-bars__label">{row.source ?? "Unknown source"}</div>
                  <div className="source-bars__track">
                    <div
                      className="source-bars__fill"
                      style={{
                        width: `${Math.max(
                          12,
                          Math.round(((row.events ?? 0) / Math.max(...sourceRows.map((item) => item.events ?? 0), 1)) * 100),
                        )}%`,
                      }}
                    />
                  </div>
                  <div className="source-bars__value">{row.events ?? 0}</div>
                </div>
              ))}
            </div>
          )}
        </article>

        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Endpoint posture</span>
              <h2 className="enterprise-panel__title">Roster status</h2>
            </div>
          </div>
          {fleetAgents.length === 0 ? (
            <div className="enterprise-empty">
              <h3>No endpoint roster available</h3>
              <p>Coverage assessment will improve once endpoint roster data is available from heartbeat reporting.</p>
            </div>
          ) : (
            <div className="roster-list">
              {fleetAgents.slice(0, 6).map((agent) => (
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
      </section>
    </div>
  );
}
