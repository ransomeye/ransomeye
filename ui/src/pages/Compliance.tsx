import { useEffect, useState } from "react";
import { fetchComplianceReport } from "../lib/client";

type Outcome = {
  prd: string;
  id: string;
  description: string;
  ok: boolean;
  error?: string;
};

export function Compliance() {
  const [outcomes, setOutcomes] = useState<Outcome[]>([]);
  const [summary, setSummary] = useState<{ total: number; passed: number; failed: number; healthy: boolean } | null>(null);

  useEffect(() => {
    fetchComplianceReport()
      .then((j) => {
        const data = j as { outcomes?: Outcome[]; summary?: { total: number; passed: number; failed: number; healthy: boolean } };
        setOutcomes(data.outcomes ?? []);
        setSummary(data.summary ?? null);
      })
      .catch(() => {
        setOutcomes([]);
        setSummary(null);
      });
  }, []);

  return (
    <div className="animate-fade-in">
      <h1 className="text-gradient u-mb-8">Compliance reports</h1>
      {summary && (
        <div className="flex-wrap-gap-12-mb-24">
          <span className={`badge ${summary.healthy ? "success" : "danger"}`}>
            {summary.healthy ? "ALL PASS" : "VIOLATIONS"}
          </span>
          <span className="badge badge--bordered">
            {summary.passed}/{summary.total} passed
          </span>
        </div>
      )}
      <div className="glass-panel glass-panel--flush">
        <table>
          <thead>
            <tr>
              <th>Requirement</th>
              <th>ID</th>
              <th>Result</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {outcomes.map((o) => (
              <tr key={`${o.prd}-${o.id}`}>
                <td>{o.prd}</td>
                <td className="font-mono">{o.id}</td>
                <td>
                  <span className={`badge ${o.ok ? "success" : "danger"}`}>{o.ok ? "PASS" : "FAIL"}</span>
                </td>
                <td className="td-muted-085">
                  {o.ok ? o.description : (o.error ?? o.description)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
