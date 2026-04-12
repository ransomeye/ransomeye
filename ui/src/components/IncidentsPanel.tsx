import { useEffect, useState, useCallback, useMemo } from "react";
import { Link } from "react-router-dom";
import { getIncidents, patchIncidentStatus, type IncidentRow } from "../lib/client";

function severityTone(severity: string): "critical" | "warning" | "stable" {
  const normalized = severity.toUpperCase();
  if (normalized === "CRITICAL" || normalized === "HIGH") return "critical";
  if (normalized === "MEDIUM") return "warning";
  return "stable";
}

function nextActions(status: string): ("INVESTIGATING" | "CONTAINED" | "RESOLVED")[] {
  const normalized = status.toUpperCase();
  if (normalized === "OPEN") return ["INVESTIGATING", "CONTAINED", "RESOLVED"];
  if (normalized === "INVESTIGATING") return ["CONTAINED", "RESOLVED"];
  if (normalized === "CONTAINED") return ["RESOLVED"];
  return [];
}

export type IncidentsPanelProps = {
  embedded?: boolean;
  reloadToken?: number;
};

export function IncidentsPanel({ embedded = false, reloadToken = 0 }: IncidentsPanelProps) {
  const [incidents, setIncidents] = useState<IncidentRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getIncidents(200);
      setIncidents(res.incidents ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch incidents");
      setIncidents([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, reloadToken]);

  const applyStatus = async (incidentId: string, status: string) => {
    setBusyId(incidentId);
    setError(null);
    try {
      await patchIncidentStatus(incidentId, status);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Status update failed");
    } finally {
      setBusyId(null);
    }
  };

  const activeCount = useMemo(
    () => incidents.filter((row) => !["RESOLVED", "CLOSED"].includes(row.status.toUpperCase())).length,
    [incidents],
  );

  return (
    <div className={embedded ? "soc-embed" : "soc-page"} id="incidents-panel-page">
      <div className="enterprise-panel__header">
        <div>
          <span className="enterprise-eyebrow">{embedded ? "Response lane" : "Response workflow"}</span>
          <h2 className="enterprise-panel__title">{embedded ? "Active incidents" : "Incidents"}</h2>
        </div>
        {!embedded && (
          <Link to="/detections" className="enterprise-panel__link">
            Review detections
          </Link>
        )}
      </div>

      {!embedded && (
        <div className="embedded-summary-grid">
          <article className="embedded-summary-card">
            <span className="embedded-summary-card__label">Visible incidents</span>
            <strong className="embedded-summary-card__value">{incidents.length}</strong>
            <span className="embedded-summary-card__meta">Current response records</span>
          </article>
          <article className="embedded-summary-card">
            <span className="embedded-summary-card__label">Still active</span>
            <strong className="embedded-summary-card__value">{activeCount}</strong>
            <span className="embedded-summary-card__meta">Open or in-progress response work</span>
          </article>
        </div>
      )}

      <div className="embedded-toolbar">
        <div className="embedded-toolbar__meta">
          {activeCount === 0 ? "No active response work is waiting for ownership." : `${activeCount} incident${activeCount === 1 ? "" : "s"} remain active.`}
        </div>
        <button type="button" className="enterprise-inline-btn" onClick={() => void load()} disabled={loading}>
          Refresh
        </button>
      </div>

      {error && (
        <div className="enterprise-inline-error">
          {error}
        </div>
      )}

      <div className="table-shell">
        <table className="soc-table soc-table--enterprise">
          <thead>
            <tr>
              <th className="soc-th">Incident</th>
              <th className="soc-th">Severity</th>
              <th className="soc-th">Status</th>
              <th className="soc-th">Owner</th>
              <th className="soc-th">Opened</th>
              <th className="soc-th">Next step</th>
            </tr>
          </thead>
          <tbody>
            {loading && incidents.length === 0 ? (
              <tr>
                <td colSpan={6} className="soc-td soc-empty-cell">
                  <div className="enterprise-empty enterprise-empty--compact">
                    <h3>Refreshing response queue</h3>
                    <p>Loading the current incident workflow state.</p>
                  </div>
                </td>
              </tr>
            ) : incidents.length === 0 ? (
              <tr>
                <td colSpan={6} className="soc-td soc-empty-cell">
                  <div className="enterprise-empty">
                    <h3>No incidents are active</h3>
                    <p>
                      No analyst-owned response records are open. Escalate directly from the alert queue when a finding
                      warrants coordinated response.
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              incidents.map((incident) => (
                <tr key={incident.incident_id}>
                  <td className="soc-td">
                    <div className="table-primary">{incident.title || incident.incident_id}</div>
                    <div className="table-secondary">{incident.incident_id}</div>
                  </td>
                  <td className="soc-td">
                    <span className={`table-pill table-pill--${severityTone(incident.severity)}`}>{incident.severity}</span>
                  </td>
                  <td className="soc-td">
                    <div className="table-primary">{incident.status}</div>
                    <div className="table-secondary">{incident.description || "Response notes not yet recorded"}</div>
                  </td>
                  <td className="soc-td">{incident.assigned_to || "Unassigned"}</td>
                  <td className="soc-td">{incident.first_seen_at ? new Date(incident.first_seen_at).toLocaleString() : "Not recorded"}</td>
                  <td className="soc-td">
                    <div className="action-pill-row">
                      {nextActions(incident.status).length === 0 ? (
                        <span className="table-secondary">No update required</span>
                      ) : (
                        nextActions(incident.status).map((status) => (
                          <button
                            key={status}
                            type="button"
                            className="enterprise-inline-btn"
                            disabled={busyId === incident.incident_id}
                            onClick={() => void applyStatus(incident.incident_id, status)}
                          >
                            {status}
                          </button>
                        ))
                      )}
                    </div>
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
