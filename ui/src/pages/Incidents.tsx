import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ClipboardCheck, ShieldAlert, TimerReset, UserRound } from "lucide-react";
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

function statusCopy(status: string): string {
  const normalized = status.toUpperCase();
  if (normalized === "OPEN") return "Waiting for analyst ownership and initial scoping";
  if (normalized === "INVESTIGATING") return "Under active validation and evidence review";
  if (normalized === "CONTAINED") return "Containment applied; closure evidence still required";
  if (normalized === "RESOLVED" || normalized === "CLOSED") return "Closed or resolved";
  return "Status pending review";
}

export function Incidents() {
  const [status, setStatus] = useState("");
  const [rows, setRows] = useState<IncidentRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await getIncidents(200);
      const filtered = status ? response.incidents.filter((row) => row.status.toUpperCase() === status.toUpperCase()) : response.incidents;
      setRows(filtered);
    } catch (loadError) {
      setRows([]);
      setError(loadError instanceof Error ? loadError.message : "Unable to load incidents");
    } finally {
      setLoading(false);
    }
  }, [status]);

  useEffect(() => {
    void load();
  }, [load]);

  const applyStatus = async (incidentId: string, nextStatus: string) => {
    setBusyId(incidentId);
    setError(null);
    try {
      await patchIncidentStatus(incidentId, nextStatus);
      await load();
    } catch (patchError) {
      setError(patchError instanceof Error ? patchError.message : "Unable to update incident status");
    } finally {
      setBusyId(null);
    }
  };

  const activeRows = useMemo(
    () => rows.filter((row) => !["RESOLVED", "CLOSED"].includes(row.status.toUpperCase())),
    [rows],
  );
  const highSeverity = rows.filter((row) => severityTone(row.severity) === "critical").length;
  const assignedCount = rows.filter((row) => row.assigned_to && row.assigned_to.trim().length > 0).length;

  return (
    <div className="soc-page">
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Incidents</h1>
          <p className="soc-page-subtitle">
            Coordinate analyst-owned response work, track lifecycle status, and close the loop on incidents that have
            already been escalated from the alert queue.
          </p>
        </div>
      </header>

      <section className="command-kpi-grid">
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--critical">
            <ShieldAlert size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Open response work</div>
            <div className="command-kpi-card__value">{activeRows.length}</div>
            <p className="command-kpi-card__copy">Incidents that still require analyst progress or closure evidence.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--warning">
            <ClipboardCheck size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">High-severity cases</div>
            <div className="command-kpi-card__value">{highSeverity}</div>
            <p className="command-kpi-card__copy">Incidents most likely to demand immediate command review.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <UserRound size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Assigned work</div>
            <div className="command-kpi-card__value">{assignedCount}</div>
            <p className="command-kpi-card__copy">Incidents already attached to a named owner or response function.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <TimerReset size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Visible records</div>
            <div className="command-kpi-card__value">{rows.length}</div>
            <p className="command-kpi-card__copy">Current working set after the lifecycle filter is applied.</p>
          </div>
        </article>
      </section>

      <section className="enterprise-panel">
        <div className="enterprise-panel__header">
          <div>
            <span className="enterprise-eyebrow">Workflow control</span>
            <h2 className="enterprise-panel__title">Incident queue</h2>
          </div>
          <Link to="/alerts" className="enterprise-panel__link">
            Review alerts
          </Link>
        </div>

        <div className="filters-bar">
          <label className="filters-bar__field">
            <span>Status filter</span>
            <select value={status} onChange={(event) => setStatus(event.target.value)} className="form-input">
              <option value="">All statuses</option>
              <option value="OPEN">Open</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="CONTAINED">Contained</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </label>
          <button type="button" className="enterprise-btn enterprise-btn--secondary" onClick={() => void load()}>
            Refresh queue
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
                <th className="soc-th">Incident</th>
                <th className="soc-th">Description</th>
                <th className="soc-th">Severity</th>
                <th className="soc-th">Status</th>
                <th className="soc-th">Owner</th>
                <th className="soc-th">Opened</th>
                <th className="soc-th">Next action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} className="soc-td soc-empty-cell">
                    <div className="enterprise-empty enterprise-empty--compact">
                      <h3>Refreshing incident queue</h3>
                      <p>Loading the current analyst-owned response workload.</p>
                    </div>
                  </td>
                </tr>
              ) : rows.length === 0 ? (
                <tr>
                  <td colSpan={7} className="soc-td soc-empty-cell">
                    <div className="enterprise-empty">
                      <h3>No incidents match this view</h3>
                      <p>
                        The response queue is clear for the selected status. Return to alerts if new findings need to be
                        escalated.
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                rows.map((row) => (
                  <tr key={row.incident_id}>
                    <td className="soc-td">
                      <div className="table-primary">{row.title || row.incident_id}</div>
                      <div className="table-secondary">{row.incident_id}</div>
                    </td>
                    <td className="soc-td">
                      <div className="table-secondary">{row.description || statusCopy(row.status)}</div>
                    </td>
                    <td className="soc-td">
                      <span className={`table-pill table-pill--${severityTone(row.severity)}`}>{row.severity}</span>
                    </td>
                    <td className="soc-td">
                      <div className="table-primary">{row.status}</div>
                      <div className="table-secondary">{statusCopy(row.status)}</div>
                    </td>
                    <td className="soc-td">{row.assigned_to || "Unassigned"}</td>
                    <td className="soc-td">{row.first_seen_at ? new Date(row.first_seen_at).toLocaleString() : "Not recorded"}</td>
                    <td className="soc-td">
                      <div className="action-pill-row">
                        {nextActions(row.status).length === 0 ? (
                          <span className="table-secondary">No further action</span>
                        ) : (
                          nextActions(row.status).map((nextStatus) => (
                            <button
                              key={nextStatus}
                              type="button"
                              className="enterprise-inline-btn"
                              disabled={busyId === row.incident_id}
                              onClick={() => void applyStatus(row.incident_id, nextStatus)}
                            >
                              {nextStatus}
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
      </section>
    </div>
  );
}
