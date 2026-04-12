/**
 * SOC API client — relative /api/v1 paths behind nginx TLS :443.
 * WebSocket: wss://<same-host>/ws (no hardcoded host or port).
 */

export const API_BASE = "/api/v1";
export const WS_BASE = `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/ws`;

export function enforceHttpsConstraints(): void {
  if (typeof globalThis === "undefined" || typeof window === "undefined") {
    return;
  }
  if (globalThis.isSecureContext) {
    return;
  }
  console.error("CRITICAL: HTTPS is strictly required. Execution blocked.");
  throw new Error("HTTPS Not Allowed");
}

export type HealthResponse = {
  status: string;
  db: boolean;
  transport: string;
  loopback: boolean;
  wal_fsync_latency_ms: number;
  event_queue_depth: number;
  batch_size: number;
  circuit_breaker: boolean;
  circuit_breaker_tripped: boolean;
  recorded_at?: string;
};

export type SystemMetricAggregate = {
  metric_name: string;
  latest_value: number;
  avg_value: number;
  min_value: number;
  max_value: number;
  sample_count: number;
  last_recorded_at: string;
};

export type SystemMetricsResponse = {
  window_seconds: number;
  metrics: SystemMetricAggregate[];
  latest: Record<string, number>;
};

export type GovernanceAuditRow = {
  audit_id: string;
  event_type: string;
  actor_id: string;
  signature_valid: boolean;
  created_at: string;
};

export type GovernanceAuditResponse = {
  total: number;
  events: GovernanceAuditRow[];
};

export type AlertRow = {
  detection_id: string;
  tenant_id: string;
  agent_id: string;
  event_id: string;
  timestamp: string;
  posterior_prob: number;
  aec_class: number;
  threat_type?: string;
  primary_signal?: string;
  analyst_disposition: string;
  logical_clock: number;
  drift_alert: boolean;
  created_at: string;
};

export type AlertsResponse = {
  total: number;
  alerts: AlertRow[];
};

export type StreamSource = "agent" | "syslog" | "netflow" | "dpi";

export type TelemetryRow = {
  event_id: string;
  tenant_id: string;
  agent_id?: string;
  probe_id?: string;
  event_type: string;
  timestamp: string;
  logical_clock: number;
  source: string;
  source_type: StreamSource;
  canonical_payload_hash: string;
  created_at: string;
};

export type TelemetryResponse = {
  data: TelemetryRow[];
  cursor: string;
  has_more: boolean;
};

export type IncidentRow = {
  incident_id: string;
  tenant_id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  assigned_to: string;
  first_seen_at: string;
  last_updated_at: string;
  created_at: string;
};

export type IncidentsResponse = {
  total: number;
  incidents: IncidentRow[];
};

export type DetectionRow = {
  id: string;
  detection_id: string;
  event_id?: string;
  agent_id: string;
  timestamp: string;
  posterior: number;
  confidence: number;
  aec_class: string;
  aec_class_index: number;
  signals: Record<string, unknown>;
  loo_importance: Record<string, unknown>;
  decision?: string;
  logical_clock: number;
  created_at?: string;
};

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API ${path} returned ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

function parseDetectionRow(raw: Record<string, unknown>): DetectionRow {
  const eventId = typeof raw.event_id === "string" ? raw.event_id : undefined;
  const detectionId = typeof raw.detection_id === "string" ? raw.detection_id : "";
  const fallbackId = eventId ?? detectionId;
  const posterior =
    typeof raw.posterior === "number"
      ? raw.posterior
      : typeof raw.confidence === "number"
        ? raw.confidence
        : Number(raw.posterior ?? raw.confidence ?? 0);

  return {
    id: typeof raw.id === "string" && raw.id.length > 0 ? raw.id : fallbackId,
    detection_id: detectionId,
    event_id: eventId,
    agent_id: typeof raw.agent_id === "string" ? raw.agent_id : "",
    timestamp: typeof raw.timestamp === "string" ? raw.timestamp : new Date(String(raw.timestamp ?? Date.now())).toISOString(),
    posterior: Number.isFinite(posterior) ? posterior : 0,
    confidence: Number.isFinite(posterior) ? posterior : 0,
    aec_class: typeof raw.aec_class === "string" ? raw.aec_class : `AEC-${Number(raw.aec_class_index ?? 0)}`,
    aec_class_index: Number.isFinite(Number(raw.aec_class_index)) ? Number(raw.aec_class_index) : 0,
    signals: raw.signals && typeof raw.signals === "object" ? (raw.signals as Record<string, unknown>) : {},
    loo_importance:
      raw.loo_importance && typeof raw.loo_importance === "object"
        ? (raw.loo_importance as Record<string, unknown>)
        : {},
    decision: typeof raw.decision === "string" ? raw.decision : undefined,
    logical_clock: Number.isFinite(Number(raw.logical_clock)) ? Number(raw.logical_clock) : 0,
    created_at: typeof raw.created_at === "string" ? raw.created_at : undefined,
  };
}

export async function getHealth(): Promise<HealthResponse> {
  return apiFetch<HealthResponse>("/system/health");
}

export async function getSystemMetrics(): Promise<SystemMetricsResponse> {
  return apiFetch<SystemMetricsResponse>("/system/metrics");
}

export async function getGovernanceAudit(limit = 100): Promise<GovernanceAuditResponse> {
  return apiFetch<GovernanceAuditResponse>(`/governance/audit?limit=${limit}`);
}

export async function getAlerts(limit = 100): Promise<AlertsResponse> {
  return apiFetch<AlertsResponse>(`/alerts?limit=${limit}`);
}

export async function getIncidents(limit = 100): Promise<IncidentsResponse> {
  return apiFetch<IncidentsResponse>(`/incidents?limit=${limit}`);
}

export async function getTelemetry(params: {
  limit?: number;
  source?: StreamSource | "";
  cursor?: string;
} = {}): Promise<TelemetryResponse> {
  const q = new URLSearchParams();
  q.set("limit", String(params.limit ?? 100));
  if (params.source) q.set("source", params.source);
  if (params.cursor) q.set("cursor", params.cursor);
  return apiFetch<TelemetryResponse>(`/telemetry?${q.toString()}`);
}

export async function fetchHealth(): Promise<HealthResponse> {
  return getHealth();
}

export async function fetchSystemHealth(): Promise<HealthResponse> {
  return getHealth();
}

export async function fetchSystemMetrics(): Promise<SystemMetricsResponse> {
  return getSystemMetrics();
}

export async function fetchGovernanceAudit(limit = 100): Promise<GovernanceAuditResponse> {
  return getGovernanceAudit(limit);
}

export async function fetchIngestionStatus(): Promise<Record<string, unknown>> {
  return apiFetch<Record<string, unknown>>("/system/ingestion-status");
}

/** Non-authoritative advisory plane visibility (read-only). */
export async function fetchShadowIntelStatus(): Promise<Record<string, unknown>> {
  return apiFetch<Record<string, unknown>>("/shadow/intelligence/status");
}

/** Read-only asset / telemetry coverage aggregates (24h window). */
export async function fetchAssetsCoverage(): Promise<Record<string, unknown>> {
  return apiFetch<Record<string, unknown>>("/assets/coverage");
}

export async function fetchRecentDetections(): Promise<DetectionRow[]> {
  const rows = await apiFetch<Record<string, unknown>[]>("/detections/recent");
  return rows.map(parseDetectionRow);
}

export async function fetchDetectionsList(params: {
  limit?: number;
  min_score?: number;
  agent_id?: string;
}): Promise<{
  total: number;
  detections: DetectionRow[];
}> {
  const rows = await fetchRecentDetections();
  const filtered = rows.filter((row) => {
    if (params.agent_id && row.agent_id !== params.agent_id) {
      return false;
    }
    if (params.min_score != null && row.posterior < params.min_score) {
      return false;
    }
    return true;
  });
  const requestedLimit = params.limit ?? filtered.length;
  const limit = Math.max(1, requestedLimit > 0 ? requestedLimit : 1);
  return {
    total: filtered.length,
    detections: filtered.slice(0, limit),
  };
}

export async function fetchIncidents(params: {
  limit?: number;
  status?: string;
}): Promise<{
  total: number;
  incidents: {
    incident_id: string;
    detection_id: string;
    agent_id: string;
    status: string;
    severity: string;
    opened_at: string;
    confidence: number;
    decision: string;
  }[];
}> {
  const q = new URLSearchParams();
  if (params.limit != null) q.set("limit", String(params.limit));
  if (params.status) q.set("status", params.status);
  const res = await fetch(`${API_BASE}/incidents?${q.toString()}`);
  if (!res.ok) throw new Error(`incidents ${res.status}`);
  const body = (await res.json()) as {
    total?: number;
    incidents?: {
      incident_id: string;
      detection_id: string;
      agent_id: string;
      status: string;
      severity: string;
      opened_at: string;
      confidence: number;
      decision: string;
    }[];
  };
  return {
    total: body.total ?? (body.incidents?.length ?? 0),
    incidents: body.incidents ?? [],
  };
}

export async function fetchFleetStatus(): Promise<Record<string, unknown>> {
  return apiFetch<Record<string, unknown>>("/fleet/status");
}

export async function fetchGovernancePolicies(): Promise<Record<string, unknown>> {
  return apiFetch<Record<string, unknown>>("/governance/policies");
}

export async function fetchComplianceReport(): Promise<Record<string, unknown>> {
  return apiFetch<Record<string, unknown>>("/compliance/report");
}

/** Static SOC governance manifest (read-only console capability metadata). */
export async function fetchGovernanceManifest(): Promise<Record<string, unknown>> {
  return apiFetch<Record<string, unknown>>("/soc/governance-manifest");
}

export async function fetchExplainabilityLOO(eventId: string): Promise<Record<string, unknown>> {
  const q = new URLSearchParams({ event_id: eventId });
  const res = await fetch(`${API_BASE}/explainability/loo?${q.toString()}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { error?: string }).error ?? `loo ${res.status}`);
  }
  return res.json();
}

export async function createIncidentFromAlert(params: {
  tenant_id: string;
  detection_id: string;
  title?: string;
  description?: string;
  severity?: string;
}): Promise<{ incident_id: string }> {
  const res = await fetch(`${API_BASE}/incidents`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      tenant_id: params.tenant_id,
      detection_id: params.detection_id,
      title: params.title ?? "",
      description: params.description ?? "",
      severity: params.severity ?? "HIGH",
    }),
  });
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`create incident ${res.status}: ${t}`);
  }
  return res.json() as Promise<{ incident_id: string }>;
}

export async function patchIncidentStatus(incidentId: string, status: string): Promise<void> {
  const res = await fetch(`${API_BASE}/incidents/${encodeURIComponent(incidentId)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ status }),
  });
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`patch incident ${res.status}: ${t}`);
  }
}
