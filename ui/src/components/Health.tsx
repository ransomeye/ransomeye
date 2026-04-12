/**
 * Health Panel — real system health sourced from /api/v1/system/health.
 */

import { useEffect, useState } from "react";
import { Activity, Database, Lock, Shield, RefreshCw } from "lucide-react";
import { fetchSystemHealth, type HealthResponse } from "../lib/client";
import { useTelemetryStream } from "../hooks/useTelemetryStream";

export function HealthPanel() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastCheck, setLastCheck] = useState<Date | null>(null);
  const { connected } = useTelemetryStream({ maxRows: 1 });

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      setLoading(true);
      try {
        const next = await fetchSystemHealth();
        if (!cancelled) {
          setHealth(next);
          setLastCheck(new Date());
        }
      } catch (error) {
        console.error(error);
        if (!cancelled) {
          setHealth(null);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const overallClass = health?.circuit_breaker_tripped ? "danger" : health?.status === "ok" ? "success" : "warning";

  return (
    <div className="animate-fade-in" id="health-page">
      <div className="flex-between-center-mb-24">
        <div className="flex-row-center-gap-12">
          <Activity size={24} color="var(--accent)" />
          <h1 className="text-gradient u-margin-0">System Health</h1>
        </div>
        <div className="flex-row-center-gap-12">
          <span className={`badge ${connected ? "success" : "danger"}`}>WS {connected ? "live" : "down"}</span>
          <button
            type="button"
            onClick={() => {
              setLoading(true);
              void fetchSystemHealth()
                .then((next) => {
                  setHealth(next);
                  setLastCheck(new Date());
                })
                .finally(() => setLoading(false));
            }}
            className="feed-control-btn"
            id="health-refresh"
            disabled={loading}
          >
            <RefreshCw size={14} className={loading ? "spin" : ""} />
            Check
          </button>
          {lastCheck && <span className="timestamp-subtle">Last: {lastCheck.toLocaleTimeString()}</span>}
        </div>
      </div>

      <div className={`glass-panel health-banner health-banner--${overallClass}`}>
        <div className={`health-indicator ${overallClass}`}>
          <Shield size={40} />
        </div>
        <div>
          <h2 className="health-title">
            Core Engine: <span className={`badge ${overallClass} badge--md`}>{health ? health.status.toUpperCase() : "UNAVAILABLE"}</span>
          </h2>
          <p className="text-secondary-p">
            {health
              ? `WAL ${health.wal_fsync_latency_ms.toFixed(3)} ms · queue ${health.event_queue_depth} · batch ${health.batch_size}`
              : "System health data unavailable."}
          </p>
        </div>
      </div>

      <div className="metrics-grid">
        <div className="glass-panel health-card">
          <div className="flex-row-center-gap-12-mb-16">
            <Database size={24} color={health?.db ? "var(--success)" : "var(--danger)"} />
            <span className="metric-title">Database Reachability</span>
          </div>
          <span className={`badge ${health?.db ? "success" : "danger"} badge--lg`}>
            {health?.db ? "CONNECTED" : "DISCONNECTED"}
          </span>
        </div>

        <div className="glass-panel health-card">
          <div className="flex-row-center-gap-12-mb-16">
            <Lock size={24} color="var(--accent)" />
            <span className="metric-title">WAL fsync latency</span>
          </div>
          <p className="health-card-note">{health ? `${health.wal_fsync_latency_ms.toFixed(3)} ms` : "—"}</p>
        </div>

        <div className="glass-panel health-card">
          <div className="flex-row-center-gap-12-mb-16">
            <Activity size={24} color="var(--accent)" />
            <span className="metric-title">Event queue depth</span>
          </div>
          <p className="health-card-note">{health ? health.event_queue_depth : "—"}</p>
        </div>

        <div className="glass-panel health-card">
          <div className="flex-row-center-gap-12-mb-16">
            <Activity size={24} color="var(--accent)" />
            <span className="metric-title">Batch size</span>
          </div>
          <p className="health-card-note">{health ? health.batch_size : "—"}</p>
        </div>

        <div className="glass-panel health-card">
          <div className="flex-row-center-gap-12-mb-16">
            <Shield size={24} color={health?.circuit_breaker_tripped ? "var(--danger)" : "var(--success)"} />
            <span className="metric-title">Circuit breaker</span>
          </div>
          <span className={`badge ${health?.circuit_breaker_tripped ? "danger" : "success"} badge--lg`}>
            {health?.circuit_breaker_tripped ? "TRIPPED" : "CLEAR"}
          </span>
        </div>
      </div>
    </div>
  );
}
