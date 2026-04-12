import { useEffect, useState, useCallback, useMemo } from "react";
import { Link } from "react-router-dom";
import { getAlerts, createIncidentFromAlert, type AlertRow } from "../lib/client";

function postureTone(row: AlertRow): "critical" | "warning" | "stable" {
  if (row.aec_class >= 3 || row.posterior_prob >= 0.85) return "critical";
  if (row.aec_class >= 2 || row.posterior_prob >= 0.6) return "warning";
  return "stable";
}

function formatPrimarySignal(alert: AlertRow): string {
  if (alert.primary_signal && alert.primary_signal.length > 0) return alert.primary_signal;
  if (alert.threat_type && alert.threat_type.length > 0) return alert.threat_type;
  return "No primary signal label";
}

export type AlertsPanelProps = {
  embedded?: boolean;
  onIncidentCreated?: () => void;
};

export function Alerts({ embedded = false, onIncidentCreated }: AlertsPanelProps) {
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getAlerts(200);
      setAlerts(res.alerts ?? []);
      setTotal(res.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load alert queue");
      setAlerts([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const criticalCount = useMemo(() => alerts.filter((row) => postureTone(row) === "critical").length, [alerts]);
  const highConfidence = useMemo(() => alerts.filter((row) => row.posterior_prob >= 0.75).length, [alerts]);

  const createIncident = async (alert: AlertRow) => {
    setBusyId(alert.detection_id);
    setError(null);
    try {
      const severity = alert.aec_class >= 3 ? "CRITICAL" : alert.aec_class === 2 ? "HIGH" : "MEDIUM";
      await createIncidentFromAlert({
        tenant_id: alert.tenant_id,
        detection_id: alert.detection_id,
        severity,
        title: `Escalated finding for ${alert.agent_id || "unknown endpoint"}`,
        description: formatPrimarySignal(alert),
      });
      onIncidentCreated?.();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to create incident");
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className={embedded ? "soc-embed" : "soc-page"} id="alerts-page">
      <div className="enterprise-panel__header">
        <div>
          <span className="enterprise-eyebrow">{embedded ? "Escalation lane" : "Triage queue"}</span>
          <h2 className="enterprise-panel__title">{embedded ? "Alert queue" : "Alerts"}</h2>
        </div>
        {!embedded && (
          <Link to="/incidents" className="enterprise-panel__link">
            Open incidents
          </Link>
        )}
      </div>

      {!embedded && (
        <div className="embedded-summary-grid">
          <article className="embedded-summary-card">
            <span className="embedded-summary-card__label">Visible alerts</span>
            <strong className="embedded-summary-card__value">{total}</strong>
            <span className="embedded-summary-card__meta">Current queue size</span>
          </article>
          <article className="embedded-summary-card">
            <span className="embedded-summary-card__label">Critical review</span>
            <strong className="embedded-summary-card__value">{criticalCount}</strong>
            <span className="embedded-summary-card__meta">Highest urgency items</span>
          </article>
          <article className="embedded-summary-card">
            <span className="embedded-summary-card__label">High confidence</span>
            <strong className="embedded-summary-card__value">{highConfidence}</strong>
            <span className="embedded-summary-card__meta">Likely escalation candidates</span>
          </article>
        </div>
      )}

      <div className="embedded-toolbar">
        <div className="embedded-toolbar__meta">
          {embedded ? `${total} visible` : "Use this queue to decide what becomes analyst-owned response work."}
        </div>
        <button type="button" className="enterprise-inline-btn" onClick={() => void load()} disabled={loading}>
          Refresh
        </button>
      </div>

      {error && (
        <div className="enterprise-inline-error" role="alert">
          {error}
        </div>
      )}

      <div className="table-shell">
        <table className="soc-table soc-table--enterprise">
          <thead>
            <tr>
              <th className="soc-th">Endpoint</th>
              <th className="soc-th">Observed</th>
              <th className="soc-th">Risk</th>
              <th className="soc-th">Confidence</th>
              <th className="soc-th">Signal</th>
              <th className="soc-th">Action</th>
            </tr>
          </thead>
          <tbody>
            {loading && alerts.length === 0 ? (
              <tr>
                <td colSpan={6} className="soc-td soc-empty-cell">
                  <div className="enterprise-empty enterprise-empty--compact">
                    <h3>Refreshing alert queue</h3>
                    <p>Loading the current set of elevated findings.</p>
                  </div>
                </td>
              </tr>
            ) : alerts.length === 0 ? (
              <tr>
                <td colSpan={6} className="soc-td soc-empty-cell">
                  <div className="enterprise-empty">
                    <h3>No elevated findings are waiting for escalation</h3>
                    <p>
                      The queue is clear. Analysts can continue through detections and operational posture review until
                      new findings arrive.
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              alerts.map((alert) => (
                <tr key={alert.detection_id}>
                  <td className="soc-td">
                    <div className="table-primary">{alert.agent_id || "Unknown endpoint"}</div>
                    <div className="table-secondary">{alert.detection_id}</div>
                  </td>
                  <td className="soc-td">{new Date(alert.timestamp).toLocaleString()}</td>
                  <td className="soc-td">
                    <span className={`table-pill table-pill--${postureTone(alert)}`}>AEC {alert.aec_class}</span>
                  </td>
                  <td className="soc-td">
                    <strong>{(alert.posterior_prob * 100).toFixed(0)}%</strong>
                  </td>
                  <td className="soc-td">
                    <div className="table-primary">{formatPrimarySignal(alert)}</div>
                    <div className="table-secondary">
                      {alert.drift_alert ? "Drift watch flagged" : "No drift warning"} · logical clock {alert.logical_clock}
                    </div>
                  </td>
                  <td className="soc-td">
                    <button
                      type="button"
                      className="enterprise-inline-btn"
                      disabled={busyId === alert.detection_id}
                      onClick={() => void createIncident(alert)}
                    >
                      {busyId === alert.detection_id ? "Escalating..." : "Escalate"}
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
