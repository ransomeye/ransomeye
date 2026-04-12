import { useEffect, useState } from "react";
import { fetchDetectionsList, fetchExplainabilityLOO } from "../lib/client";

type LOORow = {
  feature: string;
  value: number;
  impact: number;
  posterior_full: number;
  posterior_without_feat: number;
  loo_delta: number;
};

export function Explainability() {
  const [ids, setIds] = useState<string[]>([]);
  const [selected, setSelected] = useState("");
  const [loo, setLoo] = useState<{ features: LOORow[]; posterior_full: number; method: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    fetchDetectionsList({ limit: 100 })
      .then((r) => setIds(r.detections.map((d) => d.id)))
      .catch(() => setIds([]));
  }, []);

  const run = () => {
    setErr(null);
    setLoo(null);
    if (!selected.trim()) {
      setErr("Select or enter a detection reference");
      return;
    }
    fetchExplainabilityLOO(selected.trim())
      .then((j) => {
        const data = j as { features?: LOORow[]; posterior_full?: number; method?: string };
        setLoo({
          features: data.features ?? [],
          posterior_full: data.posterior_full ?? 0,
          method: data.method ?? "",
        });
      })
      .catch((e: Error) => setErr(e.message));
  };

  return (
    <div className="animate-fade-in">
      <header className="soc-page-header" style={{ marginBottom: 16 }}>
        <div>
          <h1 className="soc-page-title">Detection explainability</h1>
          <p className="soc-page-subtitle">
            Leave-one-out style attribution over pipeline feature impacts. Features render in a stable order for
            comparison. Scope is the explainability API working set—pair with full detection records for investigations.
          </p>
        </div>
      </header>

      <div className="glass-panel u-mb-16">
        <div className="flex-wrap-gap-12-center">
          <label className="label-grow-280">
            <span className="field-label">Detection reference</span>
            <input
              list="det-ids"
              value={selected}
              onChange={(e) => setSelected(e.target.value)}
              className="form-input form-input--wide"
              placeholder="Paste UUID or pick from list"
            />
            <datalist id="det-ids">
              {ids.map((id) => (
                <option key={id} value={id} />
              ))}
            </datalist>
          </label>
          <button type="button" className="btn-gradient-primary" onClick={run}>
            Run attribution
          </button>
        </div>
        {err && <p className="text-danger u-mt-12">{err}</p>}
      </div>

      {loo && (
        <div className="glass-panel u-mb-16">
          <p className="lead-muted u-mb-8">
            Model posterior (full): <strong>{loo.posterior_full.toFixed(6)}</strong>
            {loo.method ? ` · method ${loo.method}` : ""}
          </p>
          <div className="soc-scroll-page">
            <table>
              <thead>
                <tr>
                  <th>Feature</th>
                  <th>Value</th>
                  <th>Impact</th>
                  <th>Posterior w/o feature</th>
                  <th>Delta</th>
                </tr>
              </thead>
              <tbody>
                {loo.features.map((f) => (
                  <tr key={f.feature}>
                    <td className="font-mono-accent">{f.feature}</td>
                    <td>{f.value.toFixed(4)}</td>
                    <td>{f.impact.toFixed(4)}</td>
                    <td>{f.posterior_without_feat.toFixed(6)}</td>
                    <td>{f.loo_delta.toFixed(6)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
