import { useState } from "react";
import { useTelemetryStream } from "../hooks/useTelemetryStream";
import type { StreamSource, TelemetryRow } from "../lib/client";

const SOURCE_SECTIONS: Array<{ key: StreamSource; title: string }> = [
  { key: "agent", title: "Agent Events" },
  { key: "syslog", title: "Syslog Logs" },
  { key: "netflow", title: "NetFlow Flows" },
  { key: "dpi", title: "DPI Packets" },
];

function identityForRow(row: TelemetryRow): string {
  return row.agent_id ?? row.probe_id ?? "—";
}

function shortHash(hash: string): string {
  return hash.length > 12 ? `${hash.slice(0, 12)}...` : hash;
}

function filteredRows(rows: TelemetryRow[], selectedSource: string, source: StreamSource): TelemetryRow[] {
  if (selectedSource !== "" && selectedSource !== source) {
    return [];
  }
  return rows.filter((row) => row.source_type === source);
}

export function EventFeed() {
  const [selectedSource, setSelectedSource] = useState<StreamSource | "">("");
  const { rows, connected, historyAvailable, historyError } = useTelemetryStream({ maxRows: 240 });
  const visibleRows = selectedSource === "" ? rows : rows.filter((row) => row.source_type === selectedSource);

  return (
    <div className="soc-page" id="event-feed-page">
      <header className="soc-page-header">
        <div>
          <h1 className="soc-page-title">Live telemetry</h1>
          <p className="soc-page-subtitle">
            Review the real event stream arriving from collectors and runtime feeds. Historical retrieval and live
            socket status are shown separately so missing data is explicit.
          </p>
        </div>
        <div className="telemetry-toolbar">
          <label className="telemetry-filter">
            <span>Source</span>
            <select value={selectedSource} onChange={(e) => setSelectedSource(e.target.value as StreamSource | "")}>
              <option value="">All sources</option>
              {SOURCE_SECTIONS.map((section) => (
                <option key={section.key} value={section.key}>
                  {section.title}
                </option>
              ))}
            </select>
          </label>
          <span className={`soc-live ${connected ? "soc-live--on" : "soc-live--off"}`}>{connected ? "WS LIVE" : "WS OFF"}</span>
        </div>
      </header>

      {!historyAvailable && (
        <div className="enterprise-inline-error" role="alert">
          {historyError ?? "Historical telemetry retrieval is unavailable."} Live WebSocket updates can still appear
          below when the stream is connected.
        </div>
      )}

      <div className="soc-panel soc-panel--mb-pad">
        <div className="soc-panel-header-row">Deterministic order: timestamp + event_id</div>
        <div className="soc-scroll-320">
          <table className="soc-table">
            <thead>
              <tr>
                <th className="soc-th">Time</th>
                <th className="soc-th">Source</th>
                <th className="soc-th">Event ID</th>
                <th className="soc-th">Identity</th>
                <th className="soc-th">Type</th>
                <th className="soc-th">SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {visibleRows.length === 0 ? (
                <tr>
                  <td className="soc-td soc-muted" colSpan={6}>
                    {connected
                      ? "Connected and waiting for live telemetry."
                      : historyAvailable
                        ? "No telemetry events are available in the current view."
                        : "No telemetry can be shown until historical retrieval or the live socket becomes available."}
                  </td>
                </tr>
              ) : (
                visibleRows.map((row) => (
                  <tr key={row.event_id}>
                    <td className="soc-td soc-muted soc-td-11-nowrap">{row.timestamp}</td>
                    <td className="soc-td">{row.source_type}</td>
                    <td className="soc-td soc-td-mono-11">{row.event_id}</td>
                    <td className="soc-td soc-td-mono-11">{identityForRow(row)}</td>
                    <td className="soc-td">{row.event_type}</td>
                    <td className="soc-td soc-td-mono-11">{shortHash(row.canonical_payload_hash)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="telemetry-stream-grid">
        {SOURCE_SECTIONS.map((section) => {
          const sectionRows = filteredRows(rows, selectedSource, section.key).slice(0, 32);
          return (
            <div key={section.key} className="glass-panel telemetry-stream-card">
              <div className="telemetry-stream-card__head">
                <strong>{section.title}</strong>
                <span className="telemetry-stream-card__count">{sectionRows.length}</span>
              </div>
              <div className="telemetry-stream-card__body">
                {sectionRows.length === 0 ? (
                  <div className="padded-muted-16">
                    {historyAvailable || connected ? "No events in this source." : "Source data unavailable."}
                  </div>
                ) : (
                  sectionRows.map((row) => (
                    <div key={`${section.key}:${row.event_id}`} className="telemetry-stream-row">
                      <div className="telemetry-stream-row__time">{new Date(row.timestamp).toLocaleTimeString()}</div>
                      <div className="telemetry-stream-row__id">{row.event_id}</div>
                      <div className="telemetry-stream-row__meta">
                        <span>{identityForRow(row)}</span>
                        <span>{shortHash(row.canonical_payload_hash)}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
