import { startTransition, useCallback, useEffect, useRef, useState } from "react";
import { getTelemetry, type StreamSource, type TelemetryRow } from "../lib/client";
import { getWSClient, isWSStatusEvent, type WSTelemetryFrame } from "../lib/ws";

type UseTelemetryStreamOptions = {
  maxRows?: number;
  source?: StreamSource | "";
};

function timestampValue(row: TelemetryRow): number {
  const parsed = Date.parse(row.timestamp);
  return Number.isFinite(parsed) ? parsed : 0;
}

function compareTelemetryRows(a: TelemetryRow, b: TelemetryRow): number {
  const tsDelta = timestampValue(b) - timestampValue(a);
  if (tsDelta !== 0) {
    return tsDelta;
  }
  return b.event_id.localeCompare(a.event_id);
}

export function useTelemetryStream(options: UseTelemetryStreamOptions = {}) {
  const maxRows = Math.max(1, options.maxRows ?? 200);
  const source = options.source ?? "";
  const [rows, setRows] = useState<TelemetryRow[]>([]);
  const [connected, setConnected] = useState(false);
  const [historyAvailable, setHistoryAvailable] = useState(true);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const mountedRef = useRef(true);

  const mergeRows = useCallback(
    (incoming: TelemetryRow[]) => {
      if (incoming.length === 0) {
        return;
      }
      startTransition(() => {
        setRows((prev) => {
          const next = new Map<string, TelemetryRow>();
          for (const row of prev) {
            next.set(row.event_id, row);
          }
          for (const row of incoming) {
            if (source !== "" && row.source_type !== source) {
              continue;
            }
            next.set(row.event_id, row);
          }
          const merged = Array.from(next.values()).sort(compareTelemetryRows);
          if (merged.length > maxRows) {
            merged.length = maxRows;
          }
          return merged;
        });
      });
    },
    [maxRows, source]
  );

  useEffect(() => {
    mountedRef.current = true;
    setRows([]);
    setHistoryAvailable(true);
    setHistoryError(null);

    void (async () => {
      let cursor = "";
      let remaining = maxRows;
      const batch: TelemetryRow[] = [];
      while (remaining > 0) {
        const pageLimit = Math.min(remaining, 200);
        const response = await getTelemetry({
          limit: pageLimit,
          source,
          cursor: cursor || undefined,
        });
        batch.push(...response.data);
        if (!response.has_more || response.cursor === "") {
          break;
        }
        cursor = response.cursor;
        remaining = maxRows - batch.length;
      }
      if (mountedRef.current) {
        setHistoryAvailable(true);
        setHistoryError(null);
        mergeRows(batch);
      }
    })().catch((error: unknown) => {
      if (mountedRef.current) {
        setRows([]);
        setHistoryAvailable(false);
        setHistoryError(error instanceof Error ? error.message : "Historical telemetry is unavailable");
      }
    });

    return () => {
      mountedRef.current = false;
    };
  }, [maxRows, mergeRows, source]);

  useEffect(() => {
    const ws = getWSClient();
    const unsubscribe = ws.subscribe((event) => {
      if (isWSStatusEvent(event)) {
        if (event.type === "__ws_connected") {
          setConnected(true);
        } else if (event.type === "__ws_disconnected" || event.type === "__ws_max_retries") {
          setConnected(false);
        }
        return;
      }
      const frame = event as WSTelemetryFrame;
      if (source !== "" && frame.source !== source) {
        return;
      }
      mergeRows([frame.event]);
    });
    ws.connect();
    return () => {
      unsubscribe();
    };
  }, [mergeRows, source]);

  return { rows, connected, historyAvailable, historyError };
}
