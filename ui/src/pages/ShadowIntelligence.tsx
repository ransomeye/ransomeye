import { useEffect, useState } from "react";
import { EyeOff, Radar, ShieldAlert, ShieldCheck } from "lucide-react";
import { fetchShadowIntelStatus } from "../lib/client";

type ShadowPayload = {
  status?: string;
  mode?: string;
  authoritative?: boolean;
  cannot_trigger_enforcement?: boolean;
  cannot_influence_priority?: boolean;
  pipeline_healthy?: boolean;
  planes?: {
    ai_sidecar_configured?: boolean;
    dpi_plane_configured?: boolean;
    sine_sidecar_configured?: boolean;
  };
};

export function ShadowIntelligence() {
  const [data, setData] = useState<ShadowPayload | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    fetchShadowIntelStatus()
      .then((j) => {
        setData(j as ShadowPayload);
        setErr(null);
      })
      .catch((e: Error) => {
        setData(null);
        setErr(e.message);
      });
  }, []);

  return (
    <div className="soc-page">
      <div className="advisory-surface advisory-surface--advisory">
        <div className="advisory-surface__iconrow">
          <EyeOff size={28} aria-hidden />
          <ShieldAlert size={28} aria-hidden />
        </div>
        <h1 className="advisory-surface__title">Model intelligence</h1>
        <p className="advisory-surface__lead">
          <strong>Advisory plane.</strong> Experimental and secondary model signals for research—not for production
          enforcement, legal evidence priority, or incident authority on their own.
        </p>
      </div>

      {err && <p className="text-danger-mt-12">{err}</p>}

      {!data && !err && <p className="lead-muted">Loading advisory status…</p>}

      {data && (
        <>
          <section className="command-kpi-grid">
            <article className="command-kpi-card">
              <div className={`command-kpi-card__icon command-kpi-card__icon--${data.authoritative ? "critical" : "ok"}`}>
                <ShieldCheck size={18} aria-hidden />
              </div>
              <div>
                <div className="command-kpi-card__label">Authority boundary</div>
                <div className="command-kpi-card__value">{data.authoritative ? "Authoritative" : "Advisory only"}</div>
                <p className="command-kpi-card__copy">This surface must remain outside production enforcement authority.</p>
              </div>
            </article>
            <article className="command-kpi-card">
              <div className="command-kpi-card__icon command-kpi-card__icon--warning">
                <ShieldAlert size={18} aria-hidden />
              </div>
              <div>
                <div className="command-kpi-card__label">Enforcement path</div>
                <div className="command-kpi-card__value">{data.cannot_trigger_enforcement ? "Blocked" : "Review required"}</div>
                <p className="command-kpi-card__copy">Whether this advisory plane can trigger operational enforcement.</p>
              </div>
            </article>
            <article className="command-kpi-card">
              <div className={`command-kpi-card__icon command-kpi-card__icon--${data.pipeline_healthy ? "ok" : "warning"}`}>
                <Radar size={18} aria-hidden />
              </div>
              <div>
                <div className="command-kpi-card__label">Pipeline posture</div>
                <div className="command-kpi-card__value">{data.pipeline_healthy ? "Healthy" : "Degraded"}</div>
                <p className="command-kpi-card__copy">Current backend health snapshot for the advisory surface.</p>
              </div>
            </article>
          </section>

          <section className="enterprise-grid enterprise-grid--2">
            <article className="enterprise-panel">
              <div className="enterprise-panel__header">
                <div>
                  <span className="enterprise-eyebrow">Runtime status</span>
                  <h2 className="enterprise-panel__title">What is available today</h2>
                </div>
              </div>
              <dl className="detail-list">
                <div>
                  <dt>Status</dt>
                  <dd>{data.status ?? "Unavailable"}</dd>
                </div>
                <div>
                  <dt>Mode</dt>
                  <dd>{data.mode ?? "Unavailable"}</dd>
                </div>
                <div>
                  <dt>Priority influence</dt>
                  <dd>{data.cannot_influence_priority ? "Blocked" : "Review required"}</dd>
                </div>
              </dl>
            </article>

            <article className="enterprise-panel">
              <div className="enterprise-panel__header">
                <div>
                  <span className="enterprise-eyebrow">Plane configuration</span>
                  <h2 className="enterprise-panel__title">Configured components</h2>
                </div>
              </div>
              <dl className="detail-list">
                <div>
                  <dt>AI sidecar</dt>
                  <dd>{data.planes?.ai_sidecar_configured ? "Configured" : "Not configured"}</dd>
                </div>
                <div>
                  <dt>DPI plane</dt>
                  <dd>{data.planes?.dpi_plane_configured ? "Configured" : "Not configured"}</dd>
                </div>
                <div>
                  <dt>Signal plane</dt>
                  <dd>{data.planes?.sine_sidecar_configured ? "Configured" : "Not configured"}</dd>
                </div>
                <div>
                  <dt>Not yet available</dt>
                  <dd>Model findings, analyst-facing evidence, and advisory trend history are not exposed in this deployment.</dd>
                </div>
              </dl>
            </article>
          </section>
        </>
      )}
    </div>
  );
}
