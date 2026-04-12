/**
 * SOC WebSocket — same-origin wss://host/ws/events via nginx.
 * Carries normalized multi-source telemetry frames only.
 */

import { WS_BASE, type StreamSource, type TelemetryRow } from "./client";

export type WSStatusEvent = {
  type: "__ws_connected" | "__ws_disconnected" | "__ws_max_retries";
};

export type WSTelemetryFrame = {
  source: StreamSource;
  event: TelemetryRow;
};

export type WSClientEvent = WSStatusEvent | WSTelemetryFrame;
export type WSEventListener = (event: WSClientEvent) => void;

const MAX_RETRIES = 20;
const BASE_DELAY_MS = 1000;
const MAX_DELAY_MS = 30000;
const JITTER_FACTOR = 0.2;

function isStreamSource(value: unknown): value is StreamSource {
  return value === "agent" || value === "syslog" || value === "netflow" || value === "dpi";
}

function isTelemetryRow(value: unknown): value is TelemetryRow {
  if (!value || typeof value !== "object") {
    return false;
  }
  const row = value as Record<string, unknown>;
  const agentId = typeof row.agent_id === "string" ? row.agent_id : "";
  const probeId = typeof row.probe_id === "string" ? row.probe_id : "";
  return (
    typeof row.event_id === "string" &&
    typeof row.timestamp === "string" &&
    typeof row.canonical_payload_hash === "string" &&
    isStreamSource(row.source_type) &&
    (agentId.length > 0 || probeId.length > 0)
  );
}

function parseTelemetryFrame(raw: unknown): WSTelemetryFrame | null {
  if (!raw || typeof raw !== "object") {
    return null;
  }
  const frame = raw as Record<string, unknown>;
  if (!isStreamSource(frame.source) || !isTelemetryRow(frame.event)) {
    return null;
  }
  return {
    source: frame.source,
    event: frame.event,
  };
}

export function isWSStatusEvent(event: WSClientEvent): event is WSStatusEvent {
  return "type" in event;
}

export class SOCWebSocketClient {
  private ws: WebSocket | null = null;
  private listeners: Set<WSEventListener> = new Set();
  private retryCount = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private disposed = false;
  private _connected = false;

  get connected(): boolean {
    return this._connected;
  }

  subscribe(listener: WSEventListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  connect(): void {
    if (this.disposed) return;
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }
    this.doConnect();
  }

  disconnect(): void {
    this.disposed = true;
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.onclose = null;
      this.ws.onerror = null;
      this.ws.onmessage = null;
      this.ws.close();
      this.ws = null;
    }
    this._connected = false;
  }

  private doConnect(): void {
    if (this.disposed) return;

    try {
      this.ws = new WebSocket(`${WS_BASE}/events`);
    } catch {
      this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this._connected = true;
      this.retryCount = 0;
      this.dispatch({ type: "__ws_connected" });
    };

    this.ws.onclose = () => {
      this._connected = false;
      this.dispatch({ type: "__ws_disconnected" });
      this.scheduleReconnect();
    };

    this.ws.onerror = () => {};

    this.ws.onmessage = (ev: MessageEvent) => {
      try {
        const data = JSON.parse(ev.data as string) as unknown;
        const frame = parseTelemetryFrame(data);
        if (frame) {
          this.dispatch(frame);
        }
      } catch {
        /* ignore invalid frames */
      }
    };
  }

  private dispatch(event: WSClientEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        /* listener isolation */
      }
    }
  }

  private scheduleReconnect(): void {
    if (this.disposed) return;
    if (this.retryCount >= MAX_RETRIES) {
      console.error(`[WS] Max retries (${MAX_RETRIES}) reached. Stopping reconnect.`);
      this.dispatch({ type: "__ws_max_retries" });
      return;
    }

    const baseDelay = Math.min(BASE_DELAY_MS * Math.pow(2, this.retryCount), MAX_DELAY_MS);
    const jitter = 1 + JITTER_FACTOR * (Math.random() - 0.5);
    const delay = Math.round(baseDelay * jitter);

    this.retryCount++;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.doConnect();
    }, delay);
  }
}

let instance: SOCWebSocketClient | null = null;

export function getWSClient(): SOCWebSocketClient {
  if (!instance) {
    instance = new SOCWebSocketClient();
  }
  return instance;
}
