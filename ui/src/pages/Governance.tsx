import { useEffect, useMemo, useState } from "react";
import { ClipboardCheck, FileSignature, ShieldAlert, Stamp } from "lucide-react";
import { fetchGovernanceAudit, fetchGovernanceManifest, type GovernanceAuditRow } from "../lib/client";

type GovernanceManifest = {
  prd_21_ui_governance?: {
    role?: string;
    write_semantics?: string;
    write_surfaces?: string[];
    non_write_surfaces?: string;
  };
  prd_22_shadow_intelligence?: {
    route?: string;
    authoritative?: boolean;
    cannot_trigger_enforcement?: boolean;
  };
  prd_23_asset_intelligence?: {
    route?: string;
    coverage_basis?: string;
  };
  prd_25_dashboard_reporting?: {
    query_report_lineage?: {
      read_route?: string;
    };
  };
};

export function Governance() {
  const [rows, setRows] = useState<GovernanceAuditRow[]>([]);
  const [manifest, setManifest] = useState<GovernanceManifest | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchGovernanceAudit(100)
      .then((data) => {
        setRows(data.events);
        setError(null);
      })
      .catch(() => setRows([]));
    fetchGovernanceManifest()
      .then((data) => setManifest(data as GovernanceManifest))
      .catch(() => setManifest(null));
  }, []);

  const invalidCount = useMemo(() => rows.filter((row) => !row.signature_valid).length, [rows]);
  const writeSurfaces = manifest?.prd_21_ui_governance?.write_surfaces ?? [];

  return (
    <div className="soc-page">
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Governance</h1>
          <p className="soc-page-subtitle">
            Review the actual governance audit trail the backend exposes today and the deployment capability statement
            published to the UI. This page does not invent policy data that is not available from runtime routes.
          </p>
        </div>
      </header>

      <section className="command-kpi-grid">
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <Stamp size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Audit events</div>
            <div className="command-kpi-card__value">{rows.length}</div>
            <p className="command-kpi-card__copy">Recent governance or evidentiary events returned by the audit route.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className={`command-kpi-card__icon command-kpi-card__icon--${invalidCount > 0 ? "warning" : "ok"}`}>
            <FileSignature size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Invalid signatures</div>
            <div className="command-kpi-card__value">{invalidCount}</div>
            <p className="command-kpi-card__copy">Signature verification result returned by the audit records.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--neutral">
            <ClipboardCheck size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Case workflow writes</div>
            <div className="command-kpi-card__value">{writeSurfaces.length}</div>
            <p className="command-kpi-card__copy">Write routes currently declared for case workflow handling.</p>
          </div>
        </article>
        <article className="command-kpi-card">
          <div className="command-kpi-card__icon command-kpi-card__icon--warning">
            <ShieldAlert size={18} aria-hidden />
          </div>
          <div>
            <div className="command-kpi-card__label">Not available here</div>
            <div className="command-kpi-card__value">Policy catalog</div>
            <p className="command-kpi-card__copy">Policy definitions and approvals are not exposed through a dedicated UI route yet.</p>
          </div>
        </article>
      </section>

      {error && (
        <div className="enterprise-inline-error" role="alert">
          {error}
        </div>
      )}

      <section className="enterprise-grid enterprise-grid--2">
        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Observed evidence</span>
              <h2 className="enterprise-panel__title">Governance audit trail</h2>
            </div>
          </div>
          <div className="table-shell">
            <table className="soc-table soc-table--enterprise">
              <thead>
                <tr>
                  <th className="soc-th">Time</th>
                  <th className="soc-th">Event</th>
                  <th className="soc-th">Actor</th>
                  <th className="soc-th">Signature</th>
                </tr>
              </thead>
              <tbody>
                {rows.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="soc-td soc-empty-cell">
                      <div className="enterprise-empty">
                        <h3>No governance audit records are available</h3>
                        <p>The backend returned no audit rows for this window.</p>
                      </div>
                    </td>
                  </tr>
                ) : (
                  rows.map((row) => (
                    <tr key={row.audit_id}>
                      <td className="soc-td">{new Date(row.created_at).toLocaleString()}</td>
                      <td className="soc-td">{row.event_type}</td>
                      <td className="soc-td">{row.actor_id}</td>
                      <td className="soc-td">
                        <span className={`table-pill table-pill--${row.signature_valid ? "stable" : "warning"}`}>
                          {row.signature_valid ? "Valid" : "Invalid"}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </article>

        <article className="enterprise-panel">
          <div className="enterprise-panel__header">
            <div>
              <span className="enterprise-eyebrow">Deployment statement</span>
              <h2 className="enterprise-panel__title">Current console boundaries</h2>
            </div>
          </div>
          <dl className="detail-list">
            <div>
              <dt>Console role</dt>
              <dd>{manifest?.prd_21_ui_governance?.role ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Write handling</dt>
              <dd>{manifest?.prd_21_ui_governance?.write_semantics ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Read-only route coverage</dt>
              <dd>{manifest?.prd_21_ui_governance?.non_write_surfaces ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Advisory route</dt>
              <dd>{manifest?.prd_22_shadow_intelligence?.route ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Coverage route</dt>
              <dd>{manifest?.prd_23_asset_intelligence?.route ?? "Unavailable"}</dd>
            </div>
            <div>
              <dt>Reporting lineage route</dt>
              <dd>{manifest?.prd_25_dashboard_reporting?.query_report_lineage?.read_route ?? "Unavailable"}</dd>
            </div>
          </dl>

          <div className="priority-rail">
            {writeSurfaces.length === 0 ? (
              <div className="priority-rail__item">
                <div>
                  <div className="priority-rail__title">No case-workflow write routes declared</div>
                  <div className="priority-rail__copy">This deployment statement did not publish any writable case surfaces.</div>
                </div>
              </div>
            ) : (
              writeSurfaces.map((surface) => (
                <div key={surface} className="priority-rail__item">
                  <div>
                    <div className="priority-rail__title">Workflow write surface</div>
                    <div className="priority-rail__copy">{surface}</div>
                  </div>
                </div>
              ))
            )}
            <div className="priority-rail__item">
              <div>
                <div className="priority-rail__title">Not yet available in the UI</div>
                <div className="priority-rail__copy">
                  Signed policy documents, approval chains, and change-review history are not currently exposed as first-class screens.
                </div>
              </div>
            </div>
          </div>
        </article>
      </section>
    </div>
  );
}
