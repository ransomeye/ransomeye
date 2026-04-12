import { useEffect, useState } from "react";
import { Activity, Database, ShieldAlert, Waves } from "lucide-react";
import { fetchIngestionStatus } from "../lib/client";

type IngestionData = {
  events_ingested: number;
  events_dropped: number;
  enforcement_blocked: number;
  backpressure_drops?: number;
  core_queue_drops?: number;
  client_disconnects?: number;
  drop_rate_1s?: number;
  drop_rate_10s?: number;
  pipeline_healthy?: boolean;
  overall_status?: string;
  ai_plane?: string;
  dpi_plane?: string;
  sine_plane?: string;
};

export function IngestionStatus() {
  const [data, setData] = useState<IngestionData>({ events_ingested: 0, events_dropped: 0, enforcement_blocked: 0 });
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchIngestionStatus()
      .then((r) => {
        setData(r as unknown as IngestionData);
        setError(null);
      })
      .catch((loadError: Error) => {
        setError(loadError.message);
      });
  }, []);

  return (
    <div className="soc-page">
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Data flow</h1>
          <p className="soc-page-subtitle">
            Real-time ingestion posture published by the backend. This page shows only the counters and plane status the
            runtime currently exposes.
          </p>
        </div>
      </header>

      <section className="enterprise-hero">
        <div className="enterprise-hero__content">
          <span className="enterprise-eyebrow">Pipeline posture</span>
          <h2 className="enterprise-hero__title">
            {data.pipeline_healthy ? "Data flow is currently healthy." : "Data flow needs review."}
          </h2>
          <p className="enterprise-hero__copy">
            Overall status is reported directly by the ingestion status route. Use this view to confirm whether the
            pipeline is processable before relying on downstream dashboards.
          </p>
        </div>
        <div className="command-scoreboard">
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Overall state</span>
            <strong className="command-scoreboard__value">{data.overall_status ?? "Unavailable"}</strong>
            <span className="command-scoreboard__meta">{data.pipeline_healthy ? "Pipeline healthy" : "Pipeline not healthy"}</span>
          </article>
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Events ingested</span>
            <strong className="command-scoreboard__value">{data.events_ingested.toLocaleString()}</strong>
            <span className="command-scoreboard__meta">Current published ingest count</span>
          </article>
          <article className="command-scoreboard__card">
            <span className="command-scoreboard__label">Events dropped</span>
            <strong className="command-scoreboard__value">{data.events_dropped.toLocaleString()}</strong>
            <span className="command-scoreboard__meta">Direct drop counter from ingestion status</span>
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
            <Database size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Events ingested</div>
            <div className="command-kpi-card__value">{data.events_ingested.toLocaleString()}</div>
            <p className="command-kpi-card__copy">Records accepted into the pipeline during the current runtime window.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className={`command-kpi-card__icon command-kpi-card__icon--${data.events_dropped > 0 ? "critical" : "ok"}`}>
            <ShieldAlert size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Events dropped</div>
            <div className="command-kpi-card__value">{data.events_dropped.toLocaleString()}</div>
            <p className="command-kpi-card__copy">Published dropped-event count from the runtime posture route.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--warning">
            <Activity size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Enforcement blocked</div>
            <div className="command-kpi-card__value">{data.enforcement_blocked.toLocaleString()}</div>
            <p className="command-kpi-card__copy">Authoritative gating blocks currently counted by the backend.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <Waves size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Client disconnects</div>
            <div className="command-kpi-card__value">{(data.client_disconnects ?? 0).toLocaleString()}</div>
            <p className="command-kpi-card__copy">Published disconnect count for downstream clients.</p>
          </div>
        </article>
      </section>

      <section className="enterprise-grid enterprise-grid--2">
        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Published counters</span>
              <h2 className="enterprise-panel__title">Drop and pressure controls</h2>
            </div>
          </div>
          <dl className="detail-list">
            <div>
              <dt>Backpressure drops</dt>
              <dd>{data.backpressure_drops ?? 0}</dd>
            </div>
            <div>
              <dt>Core queue drops</dt>
              <dd>{data.core_queue_drops ?? 0}</dd>
            </div>
            <div>
              <dt>Drop rate 1s</dt>
              <dd>{data.drop_rate_1s ?? 0}</dd>
            </div>
            <div>
              <dt>Drop rate 10s</dt>
              <dd>{data.drop_rate_10s ?? 0}</dd>
            </div>
          </dl>
        </article>

        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Configured planes</span>
              <h2 className="enterprise-panel__title">Runtime scope</h2>
            </div>
          </div>
          <dl className="detail-list">
            <div>
              <dt>AI plane</dt>
              <dd>{data.ai_plane ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>DPI plane</dt>
              <dd>{data.dpi_plane ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Signal plane</dt>
              <dd>{data.sine_plane ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Not yet available</dt>
              <dd>Historical throughput trends and per-subscriber attribution are not exposed as dedicated UI charts yet.</dd>
            </div>
          </dl>
        </article>
      </section>
    </div>
  );
}
