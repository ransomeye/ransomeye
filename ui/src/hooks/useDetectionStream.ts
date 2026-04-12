import { useTelemetryStream } from "./useTelemetryStream";

export type DetectionStreamEvent = {
  seq: number;
  type: string;
  event_id: string;
  agent_id: string;
  timestamp: number;
  score: number;
  decision: string;
  logical_clock: number;
  canonical_payload_hash: string;
};

export function useDetectionStream(maxRows = 500) {
  const { rows, connected } = useTelemetryStream({ maxRows, source: "agent" });

  return {
    connected,
    rows: rows.map((row) => ({
      seq: row.logical_clock,
      type: row.event_type,
      event_id: row.event_id,
      agent_id: row.agent_id ?? "",
      timestamp: Math.floor(Date.parse(row.timestamp) / 1000),
      score: 0,
      decision: row.event_type,
      logical_clock: row.logical_clock,
      canonical_payload_hash: row.canonical_payload_hash,
    })),
  };
}
