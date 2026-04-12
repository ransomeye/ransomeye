import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Filter, Radar, ShieldAlert } from "lucide-react";
import { fetchDetectionsList, type DetectionRow } from "../lib/client";
import { useTelemetryStream } from "../hooks/useTelemetryStream";

function formatPercent(value: number): string {
  return `${(value * 100).toFixed(0)}%`;
}

function topFactors(signals: Record<string, unknown>): string {
  const factors = Object.entries(signals)
    .filter(([, value]) => typeof value === "number")
    .sort(([, a], [, b]) => Number(b) - Number(a))
    .slice(0, 3);

  if (factors.length === 0) return "No ranked signal factors available";
  return factors.map(([key, value]) => `${key.replaceAll("_", " ")} ${Number(value).toFixed(2)}`).join(" · ");
}

function nextStep(row: DetectionRow): string {
  if (row.posterior >= 0.85 || row.aec_class_index >= 3) return "Escalate for incident review";
  if (row.posterior >= 0.6 || row.aec_class_index >= 2) return "Validate on endpoint and compare with nearby activity";
  return "Monitor and confirm whether the pattern repeats";
}

function postureTone(row: DetectionRow): "critical" | "warning" | "stable" {
  if (row.posterior >= 0.85 || row.aec_class_index >= 3) return "critical";
  if (row.posterior >= 0.6 || row.aec_class_index >= 2) return "warning";
  return "stable";
}

export function Detections() {
  const [minScore, setMinScore] = useState(0.5);
  const [agentId, setAgentId] = useState("");
  const [total, setTotal] = useState(0);
  const [rows, setRows] = useState<DetectionRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { rows: liveTelemetry, connected, historyAvailable } = useTelemetryStream({ maxRows: 20, source: "agent" });

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await fetchDetectionsList({
        limit: 200,
        min_score: minScore,
        agent_id: agentId.trim() || undefined,
      });
      setRows(result.detections);
      setTotal(result.total);
    } catch (loadError) {
      setRows([]);
      setTotal(0);
      setError(loadError instanceof Error ? loadError.message : "Unable to load detections");
    } finally {
      setLoading(false);
    }
  }, [agentId, minScore]);

  useEffect(() => {
    void load();
  }, [load]);

  const highestPriority = rows[0] ?? null;
  const impactedAgents = useMemo(() => new Set(rows.map((row) => row.agent_id).filter(Boolean)).size, [rows]);
  const criticalCount = rows.filter((row) => postureTone(row) === "critical").length;
  const warningCount = rows.filter((row) => postureTone(row) === "warning").length;

  return (
    <div className="soc-page">
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Detections</h1>
          <p className="soc-page-subtitle">
            Review ranked findings, confirm the strongest contributing signals, and decide which items belong in the
            analyst-owned response queue.
          </p>
        </div>
        <div className="soc-page-header__meta">
          <span className={`soc-live-pill ${connected ? "soc-live-pill--on" : "soc-live-pill--off"}`}>
            <span className="soc-live-pill__dot" aria-hidden />
            {connected ? "Agent telemetry connected" : "Agent telemetry unavailable"}
          </span>
        </div>
      </header>

      <section className="command-kpi-grid">
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--critical">
            <ShieldAlert size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">High-priority findings</div>
            <div className="command-kpi-card__value">{criticalCount}</div>
            <p className="command-kpi-card__copy">Items that should be reviewed first for incident escalation.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--warning">
            <AlertTriangle size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Analyst review</div>
            <div className="command-kpi-card__value">{warningCount}</div>
            <p className="command-kpi-card__copy">Findings that require context before they are cleared or escalated.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <Radar size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Impacted endpoints</div>
            <div className="command-kpi-card__value">{impactedAgents}</div>
            <p className="command-kpi-card__copy">Distinct endpoints appearing in the current filtered working set.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <Filter size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Visible results</div>
            <div className="command-kpi-card__value">{total}</div>
            <p className="command-kpi-card__copy">Current result count after confidence and endpoint filters are applied.</p>
          </div>
        </article>
      </section>

      <section className="enterprise-grid enterprise-grid--2">
        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Review focus</span>
              <h2 className="enterprise-panel__title">First analyst read</h2>
            </div>
            <Link to="/incidents" className="enterprise-panel__link">
              Open incidents
            </Link>
          </div>
          {highestPriority ? (
            <div className={`priority-summary priority-summary--${postureTone(highestPriority)}`}>
              <div className="priority-summary__label">Top ranked finding</div>
              <div className="priority-summary__title">{highestPriority.agent_id || "Unattributed endpoint"}</div>
              <div className="priority-summary__meta">
                {highestPriority.aec_class} · {formatPercent(highestPriority.posterior)} confidence ·{" "}
                {new Date(highestPriority.timestamp).toLocaleString()}
              </div>
              <p className="priority-summary__copy">{topFactors(highestPriority.signals)}</p>
              <div className="priority-summary__next">{nextStep(highestPriority)}</div>
            </div>
          ) : (
            <div className="enterprise-empty">
              <h3>No detections match the current filters</h3>
              <p>Broaden the confidence threshold or remove the endpoint filter to repopulate the review queue.</p>
            </div>
          )}
        </article>

        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Live context</span>
              <h2 className="enterprise-panel__title">Recent endpoint activity</h2>
            </div>
          </div>
          {liveTelemetry.length === 0 ? (
            <div className="enterprise-empty enterprise-empty--compact">
              <h3>{historyAvailable ? "No live telemetry sample" : "Telemetry history unavailable"}</h3>
              <p>
                {connected
                  ? "The socket is connected. This panel will fill as new endpoint activity reaches the stream."
                  : historyAvailable
                    ? "Telemetry will appear here as endpoint activity reaches the stream."
                    : "Historical telemetry retrieval failed, so this panel can only populate from new live events."}
              </p>
            </div>
          ) : (
            <div className="mini-stream">
              {liveTelemetry.slice(0, 8).map((row) => (
                <div key={row.event_id} className="mini-stream__row">
                  <div>
                    <div className="mini-stream__title">{row.event_type}</div>
                    <div className="mini-stream__meta">{row.agent_id || "Unknown endpoint"}</div>
                  </div>
                  <div className="mini-stream__time">{new Date(row.timestamp).toLocaleTimeString()}</div>
                </div>
              ))}
            </div>
          )}
        </article>
      </section>

      <section className="enterprise-panel">
        <div className="enterprise-panel__header">
          <div>
            <span className="enterprise-eyebrow">Filters</span>
            <h2 className="enterprise-panel__title">Detection review queue</h2>
          </div>
        </div>

        <div className="filters-bar">
          <label className="filters-bar__field">
            <span>Minimum confidence</span>
            <input
              type="number"
              min={0}
              max={1}
              step={0.05}
              value={minScore}
              onChange={(event) => {
                setMinScore(Number(event.target.value) || 0);
              }}
              className="form-input"
            />
          </label>
          <label className="filters-bar__field filters-bar__field--wide">
            <span>Endpoint</span>
            <input
              type="text"
              value={agentId}
              onChange={(event) => {
                setAgentId(event.target.value);
              }}
              placeholder="Filter by endpoint identifier"
              className="form-input"
            />
          </label>
          <button type="button" className="enterprise-btn enterprise-btn--secondary" onClick={() => void load()}>
            Refresh results
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
                <th className="soc-th">Risk class</th>
                <th className="soc-th">Confidence</th>
                <th className="soc-th">Leading factors</th>
                <th className="soc-th">Next action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6} className="soc-td soc-empty-cell">
                    <div className="enterprise-empty enterprise-empty--compact">
                      <h3>Refreshing detection queue</h3>
                      <p>Updating the ranked working set for the current filters.</p>
                    </div>
                  </td>
                </tr>
              ) : rows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="soc-td soc-empty-cell">
                    <div className="enterprise-empty">
                      <h3>No detections match this view</h3>
                      <p>Try lowering the confidence threshold or removing the endpoint filter to review more results.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                rows.map((row) => (
                  <tr key={row.id}>
                    <td className="soc-td">
                      <div className="table-primary">{row.agent_id || "Unknown endpoint"}</div>
                      <div className="table-secondary">{row.detection_id}</div>
                    </td>
                    <td className="soc-td">{new Date(row.timestamp).toLocaleString()}</td>
                    <td className="soc-td">
                      <span className={`table-pill table-pill--${postureTone(row)}`}>{row.aec_class}</span>
                    </td>
                    <td className="soc-td">
                      <strong>{formatPercent(row.posterior)}</strong>
                    </td>
                    <td className="soc-td">
                      <div className="table-secondary">{topFactors(row.signals)}</div>
                    </td>
                    <td className="soc-td">
                      <div className="table-secondary">{nextStep(row)}</div>
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
