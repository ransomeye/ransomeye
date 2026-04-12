package soc

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ransomeye/core/internal/api"
	"ransomeye/core/internal/backpressure"
	"ransomeye/core/internal/config"
	rcrypto "ransomeye/core/internal/crypto"
	"ransomeye/core/internal/enforcement"
	"ransomeye/core/internal/health"
	"ransomeye/core/internal/metrics"
	"ransomeye/core/internal/pipeline"
)

const (
	recentRingSize            = 100
	perClientQueueSize        = 1
	wsWriteDeadline           = 100 * time.Millisecond
	systemMetricInterval      = 5 * time.Second
	telemetryPublishInterval  = 50 * time.Millisecond
	governancePublishInterval = 2 * time.Second
	heartbeatPublishInterval  = 5 * time.Second
	maxTailBatch              = 200
)

type ServerOptions struct {
	Addr            string
	Events          <-chan *pipeline.EventEnvelope
	EventHub        *pipeline.Hub
	DBPool          *pgxpool.Pool
	WORM            *rcrypto.WORM
	WORMStoragePath string
	// EnforcementDispatcher optional; used for read-only runtime route observability (PRD-12).
	EnforcementDispatcher *enforcement.ActionDispatcher
}

type Server struct {
	addr               string
	events             <-chan *pipeline.EventEnvelope
	eventHub           *pipeline.Hub
	wsStream           <-chan *pipeline.EventEnvelope
	pool               *pgxpool.Pool
	worm               *rcrypto.WORM
	backpressureEngine *backpressure.Engine
	// wormStorageRoot is the filesystem root for sealed blobs (WORM_STORAGE_PATH).
	wormStorageRoot string

	enforcement *enforcement.ActionDispatcher

	httpServer *http.Server

	upgrader websocket.Upgrader

	mu      sync.RWMutex
	clients map[*wsClient]struct{}
	cache   detectionCache

	metricMu           sync.Mutex
	lastMetricSample   time.Time
	lastEventsIngested uint64
	haveBatchBaseline  bool
}

type ingestionStatusResponse struct {
	EventsIngested             uint64 `json:"events_ingested"`
	EventsDropped              uint64 `json:"events_dropped"`
	EnforcementBlocked         uint64 `json:"enforcement_blocked"`
	BackpressureDrops          uint64 `json:"backpressure_drops"`
	DPIPacketsTotal            uint64 `json:"dpi_packets_total"`
	DPIPacketsDropped          uint64 `json:"dpi_packets_dropped"`
	DPIDropRatio               uint64 `json:"dpi_drop_ratio"`
	DPIThrottleMode            uint32 `json:"dpi_throttle_mode"`
	DPISamplingRate            uint32 `json:"dpi_sampling_rate"`
	DPIControlLatency          uint64 `json:"dpi_control_latency"`
	CoreQueueDrops             uint64 `json:"core_queue_drops"`
	PerSubscriberDrops         uint64 `json:"per_subscriber_drops"`
	CriticalPerSubscriberDrops uint64 `json:"critical_per_subscriber_drops"`
	ClientDisconnects          uint64 `json:"client_disconnects"`
	DropRate1s                 uint64 `json:"drop_rate_1s"`
	DropRate10s                uint64 `json:"drop_rate_10s"`
	SINEFailuresTotal          uint64 `json:"sine_failures_total"`
	SINEState                  string `json:"sine_state"`
	AIPlane                    string `json:"ai_plane"`
	DPIPlane                   string `json:"dpi_plane"`
	SINEPlane                  string `json:"sine_plane"`
	DPIMetricsScope            string `json:"dpi_metrics_scope"`
	PipelineHealthy            bool   `json:"pipeline_healthy"`
	OverallStatus              string `json:"overall_status"`
	ComplianceBootstrapOK      bool   `json:"compliance_bootstrap_ok"`
	AirGapPosture              string `json:"air_gap_posture"`
	AirGapDetail               string `json:"air_gap_detail,omitempty"`
	EnforcementDispatchGateBlocked bool   `json:"enforcement_dispatch_gate_blocked"`
	EnforcementDispatchGateReason  string `json:"enforcement_dispatch_gate_reason,omitempty"`
	AuthoritativeDecisionPath      string `json:"authoritative_decision_path"`
	IsolationSimulationGateScope   string `json:"isolation_simulation_gate_scope"`
}

type explanationFeat struct {
	Feature string  `json:"feature"`
	Impact  float64 `json:"impact"`
	Value   float64 `json:"value"`
}

type recentDetection struct {
	ID          string            `json:"id"`
	Timestamp   time.Time         `json:"timestamp"`
	Confidence  float64           `json:"confidence"`
	AgentID     string            `json:"agent_id,omitempty"`
	Decision    string            `json:"decision,omitempty"`
	Explanation []explanationFeat `json:"explanation,omitempty"`
}

// wsDetectionPayload mirrors pipeline.canonicalDetectionPayload for SOC cache hydration.
type wsDetectionPayload struct {
	EventID     string            `json:"event_id"`
	AgentID     string            `json:"agent_id"`
	Score       float64           `json:"score"`
	Decision    string            `json:"decision"`
	Timestamp   int64             `json:"timestamp"`
	Explanation []explanationFeat `json:"explanation"`
}

type wsTelemetryFrame struct {
	Source string       `json:"source"`
	Event  TelemetryRow `json:"event"`
}

type detectionCache struct {
	ring [recentRingSize]recentDetection
	idx  int
	size int
}

func (c *detectionCache) append(d recentDetection) {
	c.ring[c.idx] = d
	c.idx = (c.idx + 1) % len(c.ring)
	if c.size < len(c.ring) {
		c.size++
	}
}

func (c *detectionCache) snapshotNewestFirst() []recentDetection {
	out := make([]recentDetection, 0, c.size)
	for i := 0; i < c.size; i++ {
		pos := (c.idx - 1 - i + len(c.ring)) % len(c.ring)
		out = append(out, c.ring[pos])
	}
	return out
}

type wsClient struct {
	id         int64
	conn       *websocket.Conn
	queue      chan []byte
	done       chan struct{}
	closeOnce  sync.Once
	replayReqs int32
}

type metricSample struct {
	Name         string
	Component    string
	Value        float64
	RecordedAt   time.Time
	LogicalClock int64
}

type tailCursor struct {
	Timestamp time.Time
	ID        string
}

func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Events == nil {
		return nil, errors.New("events subscription channel is required")
	}

	cfg := config.MustGetVerified()
	addr := cfg.Network.SOCListenAddr

	wormRoot := strings.TrimSpace(opts.WORMStoragePath)
	if wormRoot == "" {
		wormRoot = strings.TrimSpace(os.Getenv("WORM_STORAGE_PATH"))
	}
	if opts.WORM != nil && wormRoot == "" {
		return nil, errors.New("SOC server: WORM enabled but WORM_STORAGE_PATH / WORMStoragePath is empty")
	}

	s := &Server{
		addr:               addr,
		events:             opts.Events,
		eventHub:           opts.EventHub,
		pool:               opts.DBPool,
		worm:               opts.WORM,
		enforcement:        opts.EnforcementDispatcher,
		backpressureEngine: backpressure.NewEngine(),
		wormStorageRoot:    wormRoot,
		clients:            make(map[*wsClient]struct{}),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(*http.Request) bool { return true },
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.handleHealthFull)
	mux.HandleFunc("GET /api/v1/system/health", s.handleSystemHealth)
	mux.HandleFunc("GET /api/v1/system/metrics", s.handleSystemMetrics)
	mux.HandleFunc("GET /api/v1/system/ingestion-status", s.handleIngestionStatus)
	mux.HandleFunc("GET /api/v1/detections/recent", s.handleRecentDetections)
	mux.HandleFunc("GET /api/v1/detections/list", s.handleDetectionsList)
	mux.HandleFunc("GET /api/v1/alerts", s.handleAlertsDB)
	mux.HandleFunc("GET /api/v1/incidents", s.handleIncidentsDB)
	mux.HandleFunc("POST /api/v1/incidents", s.handleCreateIncident)
	mux.HandleFunc("PATCH /api/v1/incidents/{id}", s.handlePatchIncident)
	mux.HandleFunc("GET /api/v1/telemetry", s.handleTelemetryDB)
	mux.HandleFunc("GET /api/events", s.handleTelemetryDB)
	mux.HandleFunc("GET /api/v1/fleet/status", s.handleFleetStatus)
	mux.HandleFunc("GET /api/v1/shadow/intelligence/status", s.handleShadowIntelStatus)
	mux.HandleFunc("GET /api/v1/assets/coverage", s.handleAssetsCoverage)
	mux.HandleFunc("GET /api/v1/soc/governance-manifest", s.handleSocGovernanceManifest)
	mux.HandleFunc("GET /api/v1/reporting/lineage", s.handleReportingLineage)
	mux.HandleFunc("GET /api/v1/enforcement/registered-agents", s.handleEnforcementRegisteredAgents)
	mux.HandleFunc("GET /api/v1/governance/audit", s.handleGovernanceAudit)
	mux.HandleFunc("GET /api/v1/governance/policies", s.handleGovernancePolicies)
	mux.HandleFunc("GET /api/v1/compliance/report", s.handleComplianceReport)
	mux.HandleFunc("GET /api/v1/explainability/loo", s.handleExplainabilityLOO)
	fh := api.NewForensicsHandler(s.pool)
	mux.HandleFunc("GET /api/v1/forensics/export/{evidence_id}", fh.ExportForEvidence)
	mux.HandleFunc("GET /ws", s.handleWS)
	mux.HandleFunc("GET /ws/events", s.handleWS)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      requireLoopback(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if s.eventHub != nil {
		s.attachPipelineStream(s.eventHub)
	}
	return s, nil
}

func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip := net.ParseIP(r.RemoteAddr)
		return ip != nil && ip.IsLoopback()
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func requireLoopback(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/ws") {
			if !isLoopbackRequest(r) {
				http.Error(w, "forbidden — loopback only", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) Serve(ctx context.Context) error {
	if s == nil || s.httpServer == nil {
		return errors.New("server not initialized")
	}

	errCh := make(chan error, 1)

	go s.eventLoop(ctx)
	go s.systemMetricLoop(ctx)
	go s.telemetryLoop(ctx)
	go s.governanceLoop(ctx)
	go s.heartbeatLoop(ctx)

	go func() {
		log.Printf("SOC server running on http://%s (plaintext)", s.addr)
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("SOC server failed: %v", err)
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.httpServer == nil {
		return nil
	}
	if s.eventHub != nil {
		if s.wsStream != nil {
			s.eventHub.Unsubscribe(s.wsStream)
		}
		if s.events != nil {
			s.eventHub.Unsubscribe(s.events)
		}
	}
	s.closeAllClients()
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleHealthFull(w http.ResponseWriter, r *http.Request) {
	dbOK := poolHealthy(r.Context(), s.pool)
	st := health.GetSystemState()
	pipelineOK := st != nil && st.PipelineHealthy
	status := "ok"
	if !health.SliceTelemetryOK(dbOK, pipelineOK) || health.AirGapDegradesHealth() {
		status = "degraded"
	}
	wormOK := s.worm != nil && s.wormStorageRoot != ""
	wormKeyMaterialOK := rcrypto.WormSigningKeyMaterialOK()

	var merkleRoot, merkleComputedAt string
	var merkleLeafCount int
	if s.pool != nil {
		ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout)
		err := s.pool.QueryRow(ctx, `
SELECT merkle_root, leaf_count, computed_at::text
FROM merkle_daily_roots
ORDER BY computed_at DESC
LIMIT 1`).Scan(&merkleRoot, &merkleLeafCount, &merkleComputedAt)
		cancel()
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			merkleRoot, merkleComputedAt, merkleLeafCount = "", "", 0
		}
	}

	hubDepth := 0
	if s.eventHub != nil {
		hubDepth = s.eventHub.SubscriberQueueDepth()
	}
	wsQueued := 0
	s.mu.RLock()
	for c := range s.clients {
		wsQueued += len(c.queue)
	}
	s.mu.RUnlock()

	gateBlocked, gateReason := EnforcementDispatchGateView()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                    status,
		"db":                        dbOK,
		"pipeline_healthy":          pipelineOK,
		"ai_configured":             health.AIPlaneEnvConfigured(),
		"ai_ready":                  st != nil && st.AIReady,
		"sine_configured":           health.SINEPlaneEnvConfigured(),
		"sine_ready":                st != nil && st.SINEReady,
		"dpi_configured":            health.DPIPlaneEnvConfigured(),
		"dpi_ready":                 st != nil && st.DPIReady,
		"compliance_bootstrap_ok":   health.ComplianceBootstrapOK(),
		"transport":                 "http_plaintext",
		"loopback":                  true,
		"worm_ok":                   wormOK,
		"worm_key_material_ok":      wormKeyMaterialOK,
		"merkle_root_latest":        merkleRoot,
		"merkle_leaf_count_latest":  merkleLeafCount,
		"merkle_computed_at":        merkleComputedAt,
		"event_hub_queue_depth":     hubDepth,
		"soc_replay_ring_capacity":  recentRingSize,
		"ws_subscriber_queue_depth": wsQueued,
		"air_gap_posture":           health.AirGapPosture(),
		"air_gap_detail":            health.AirGapDetail(),
		"enforcement_dispatch_gate_blocked": gateBlocked,
		"enforcement_dispatch_gate_reason":  gateReason,
		"authoritative_decision_path":         AuthoritativeDecisionPath,
		"isolation_simulation_gate_scope":     IsolationSimulationGateScope,
	})
}

func (s *Server) handleIngestionStatus(w http.ResponseWriter, r *http.Request) {
	st := health.GetSystemState()
	pipelineOK := st != nil && st.PipelineHealthy
	dbOK := poolHealthy(r.Context(), s.pool)
	top := "ok"
	if !health.SliceTelemetryOK(dbOK, pipelineOK) || health.AirGapDegradesHealth() {
		top = "degraded"
	}
	dpiConfigured := health.DPIPlaneEnvConfigured()
	sineConfigured := health.SINEPlaneEnvConfigured()
	var dpiTotal, dpiDropped, dpiDropRatio uint64
	var dpiThrottle, dpiSample uint32
	var dpiCtrlLat uint64
	if dpiConfigured {
		dpiTotal = metrics.DPIPacketsTotal()
		dpiDropped = metrics.DPIPacketsDropped()
		dpiDropRatio = metrics.DPIDropRatio()
		dpiThrottle = metrics.DPIThrottleMode()
		dpiSample = metrics.DPISamplingRate()
		dpiCtrlLat = metrics.DPIControlLatency()
	}
	var sineFailures uint64
	if sineConfigured {
		sineFailures = metrics.SINEFailuresTotal()
	}
	gateBlocked, gateReason := EnforcementDispatchGateView()
	writeJSON(w, http.StatusOK, ingestionStatusResponse{
		EventsIngested:             metrics.EventsIngested(),
		EventsDropped:              metrics.EventsDropped(),
		EnforcementBlocked:         metrics.EnforcementBlocked(),
		BackpressureDrops:          metrics.BackpressureDrops(),
		DPIPacketsTotal:            dpiTotal,
		DPIPacketsDropped:          dpiDropped,
		DPIDropRatio:               dpiDropRatio,
		DPIThrottleMode:            dpiThrottle,
		DPISamplingRate:            dpiSample,
		DPIControlLatency:          dpiCtrlLat,
		CoreQueueDrops:             metrics.CoreQueueDrops(),
		PerSubscriberDrops:         metrics.PerSubscriberDrops(),
		CriticalPerSubscriberDrops: metrics.CriticalPerSubscriberDrops(),
		ClientDisconnects:          metrics.ClientDisconnects(),
		DropRate1s:                 metrics.DropRate1s(),
		DropRate10s:                metrics.DropRate10s(),
		SINEFailuresTotal:          sineFailures,
		SINEState:                  ingestionSINEStateLine(),
		AIPlane:                    optionalPlaneLabel(health.AIPlaneEnvConfigured()),
		DPIPlane:                   optionalPlaneLabel(dpiConfigured),
		SINEPlane:                  optionalPlaneLabel(sineConfigured),
		DPIMetricsScope:            dpiMetricsScope(),
		PipelineHealthy:            pipelineOK,
		OverallStatus:              top,
		ComplianceBootstrapOK:      health.ComplianceBootstrapOK(),
		AirGapPosture:              health.AirGapPosture(),
		AirGapDetail:               health.AirGapDetail(),
		EnforcementDispatchGateBlocked: gateBlocked,
		EnforcementDispatchGateReason:  gateReason,
		AuthoritativeDecisionPath:      AuthoritativeDecisionPath,
		IsolationSimulationGateScope:   IsolationSimulationGateScope,
	})
}

func (s *Server) handleRecentDetections(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), dbQueryTimeout)
	defer cancel()

	out, err := s.queryRecentDetections(ctx, defaultResultLimit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "query failed",
		})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	client := &wsClient{
		id:    time.Now().UnixNano(),
		conn:  conn,
		queue: make(chan []byte, perClientQueueSize),
		done:  make(chan struct{}),
	}

	s.mu.Lock()
	s.clients[client] = struct{}{}
	s.mu.Unlock()

	go s.readPump(client)
	go s.writePump(client)
}

func (s *Server) readPump(client *wsClient) {
	defer s.removeClient(client)
	for {
		if _, _, err := client.conn.ReadMessage(); err != nil {
			return
		}
	}
}

func (s *Server) writePump(client *wsClient) {
	defer s.removeClient(client)
	for {
		select {
		case <-client.done:
			return
		case msg := <-client.queue:
			// Copy at websocket write boundary (defensive): the payload is immutable, but this prevents
			// any unexpected retention/mutation by downstream libraries from affecting other clients.
			out := make([]byte, len(msg))
			copy(out, msg)
			_ = client.conn.SetWriteDeadline(time.Now().Add(wsWriteDeadline))
			if err := client.conn.WriteMessage(websocket.TextMessage, out); err != nil {
				_ = client.conn.Close()
				return
			}
		}
	}
}

func (s *Server) removeClient(client *wsClient) {
	s.mu.Lock()
	if _, ok := s.clients[client]; !ok {
		s.mu.Unlock()
		return
	}
	delete(s.clients, client)
	s.mu.Unlock()
	client.closeOnce.Do(func() {
		close(client.done)
		_ = client.conn.Close()
	})
}

func (s *Server) closeAllClients() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.clients {
		c.closeOnce.Do(func() {
			close(c.done)
			_ = c.conn.Close()
		})
		delete(s.clients, c)
	}
}

func (s *Server) snapshotClients() []*wsClient {
	s.mu.RLock()
	defer s.mu.RUnlock()
	clients := make([]*wsClient, 0, len(s.clients))
	for client := range s.clients {
		clients = append(clients, client)
	}
	return clients
}

func (s *Server) attachPipelineStream(hub *pipeline.Hub) {
	if s == nil || hub == nil || s.wsStream != nil {
		return
	}

	ch := make(chan *pipeline.EventEnvelope, 1024)
	s.wsStream = hub.Subscribe(ch)

	go func(stream <-chan *pipeline.EventEnvelope) {
		for env := range stream {
			if env == nil {
				continue
			}
			evt := normalizeEvent(env)
			env.Release()
			if evt != nil {
				s.broadcast(evt)
			}
		}
	}(s.wsStream)
}

func normalizeEvent(env *pipeline.EventEnvelope) map[string]any {
	if env == nil || env.Type != "telemetry" || !isAllowedTelemetrySource(env.SourceType) {
		return nil
	}

	eventID := strings.TrimSpace(env.EventID)
	sourceType := strings.TrimSpace(env.SourceType)
	timestamp := env.Timestamp.UTC().Format(time.RFC3339Nano)
	canonicalPayloadHash := strings.TrimSpace(env.Target)
	if canonicalPayloadHash == "" && len(env.Payload) > 0 {
		digest := sha256.Sum256(env.Payload)
		canonicalPayloadHash = fmt.Sprintf("%x", digest)
	}
	if eventID == "" || sourceType == "" || timestamp == "" || canonicalPayloadHash == "" {
		return nil
	}

	event := map[string]any{
		"event_id":               eventID,
		"source_type":            sourceType,
		"timestamp":              timestamp,
		"canonical_payload_hash": canonicalPayloadHash,
	}

	agentID, probeID := telemetryIdentityFields(sourceType, env.AgentID)
	if agentID != "" {
		event["agent_id"] = agentID
	}
	if probeID != "" {
		event["probe_id"] = probeID
	}
	if _, ok := event["agent_id"]; !ok {
		if _, ok := event["probe_id"]; !ok {
			return nil
		}
	}

	return map[string]any{
		"source": sourceType,
		"event":  event,
	}
}

func (s *Server) enqueueClientPayload(client *wsClient, payload []byte) {
	if client == nil {
		return
	}

	incremented := false
	select {
	case <-client.done:
		return
	case client.queue <- payload:
		return
	default:
		if s.backpressureEngine != nil {
			s.backpressureEngine.IncrementPressure("ws client slow")
			incremented = true
		}
		select {
		case <-client.done:
		case client.queue <- payload:
		}
	}
	if incremented && s.backpressureEngine != nil {
		s.backpressureEngine.DecrementPressure()
	}
}

func (s *Server) broadcast(evt map[string]any) {
	if evt == nil {
		return
	}

	payload, err := json.Marshal(evt)
	if err != nil {
		return
	}

	for _, client := range s.snapshotClients() {
		s.enqueueClientPayload(client, payload)
	}
}

func (s *Server) eventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case env, ok := <-s.events:
			if !ok {
				return
			}
			if env == nil || len(env.Payload) == 0 {
				if env != nil {
					env.Release()
				}
				continue
			}
			if env.Type == "detection" {
				d := recentDetection{
					ID:         env.Target,
					Timestamp:  env.Timestamp.UTC(),
					Confidence: 0,
				}
				var p wsDetectionPayload
				if json.Unmarshal(env.Payload, &p) == nil && p.EventID != "" {
					d.ID = p.EventID
					d.AgentID = p.AgentID
					d.Confidence = p.Score
					d.Decision = p.Decision
					d.Explanation = append([]explanationFeat(nil), p.Explanation...)
					if p.Timestamp > 0 {
						d.Timestamp = time.Unix(p.Timestamp, 0).UTC()
					}
				}
				s.mu.Lock()
				s.cache.append(d)
				s.mu.Unlock()
			}

			env.Release() // subscriber done with envelope
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) publishEnvelope(env *pipeline.EventEnvelope) {
	if env == nil {
		return
	}

	if s.eventHub == nil {
		env.Release()
		return
	}

	incremented := false
	for {
		err := s.eventHub.TryPublish(env)
		if err == nil {
			if incremented && s.backpressureEngine != nil {
				s.backpressureEngine.DecrementPressure()
			}
			env.Release()
			return
		}
		if !incremented && s.backpressureEngine != nil {
			s.backpressureEngine.IncrementPressure("soc hub backpressure")
			incremented = true
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *Server) buildSystemMetricEnvelope(sample metricSample) *pipeline.EventEnvelope {
	status := strconv.FormatFloat(sample.Value, 'f', -1, 64)
	if sample.Name == "circuit_breaker_tripped" {
		if sample.Value >= 0.5 {
			status = "true"
		} else {
			status = "false"
		}
	}
	eventID := fmt.Sprintf("%s:%d", sample.Name, sample.LogicalClock)
	return pipeline.GetEventEnvelope(
		sample.LogicalClock,
		"system_metric",
		eventID,
		sample.Component,
		sample.Name,
		"system",
		sample.Component,
		status,
		sample.RecordedAt,
		sample.LogicalClock,
		pipeline.PriorityNormal,
	)
}

func (s *Server) buildTelemetryEnvelope(eventID, identity, eventType, sourceType, canonicalPayloadHash string, logicalClock int64, ts time.Time) *pipeline.EventEnvelope {
	return pipeline.GetEventEnvelope(
		logicalClock,
		"telemetry",
		eventID,
		identity,
		eventType,
		sourceType,
		canonicalPayloadHash,
		"ingested",
		ts,
		logicalClock,
		pipeline.PriorityNormal,
	)
}

func (s *Server) buildGovernanceEnvelope(auditID, tenantID, eventType, actorID string, signatureValid bool, createdAt time.Time) *pipeline.EventEnvelope {
	status := "invalid"
	if signatureValid {
		status = "valid"
	}
	logicalClock := createdAt.UTC().UnixMilli()
	return pipeline.GetEventEnvelope(
		logicalClock,
		"governance_event",
		auditID,
		actorID,
		eventType,
		"governance",
		tenantID,
		status,
		createdAt,
		logicalClock,
		pipeline.PriorityNormal,
	)
}

func (s *Server) buildHeartbeatEnvelope(agentID, hostname, status string, logicalClock int64, heartbeatAt time.Time) *pipeline.EventEnvelope {
	eventID := fmt.Sprintf("%s:%d", agentID, logicalClock)
	return pipeline.GetEventEnvelope(
		logicalClock,
		"heartbeat",
		eventID,
		agentID,
		"heartbeat",
		"agent",
		hostname,
		status,
		heartbeatAt,
		logicalClock,
		pipeline.PriorityNormal,
	)
}

func (s *Server) resolveMetricsTenantID(ctx context.Context) (string, error) {
	if s == nil || s.pool == nil {
		return "", errors.New("database pool not available")
	}
	queries := []string{
		`SELECT tenant_id::text FROM system_metrics ORDER BY metric_time DESC LIMIT 1`,
		`SELECT tenant_id::text FROM ingestion_stats ORDER BY stat_time DESC LIMIT 1`,
		`SELECT tenant_id::text FROM telemetry_events ORDER BY created_at DESC LIMIT 1`,
		`SELECT tenant_id::text FROM detections ORDER BY created_at DESC LIMIT 1`,
		`SELECT tenant_id::text FROM governance_audit_log ORDER BY created_at DESC LIMIT 1`,
		`SELECT tenant_id::text FROM agent_sessions ORDER BY updated_at DESC LIMIT 1`,
	}
	for _, q := range queries {
		var tenantID string
		if err := s.pool.QueryRow(ctx, q).Scan(&tenantID); err == nil && tenantID != "" {
			return tenantID, nil
		}
	}
	return "", errors.New("no tenant context available for system metrics")
}

func (s *Server) queryWALFsyncLatency(ctx context.Context) (float64, error) {
	if s == nil || s.pool == nil {
		return 0, errors.New("database pool not available")
	}
	var latency float64
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(
			CASE
				WHEN wal_sync = 0 THEN 0
				ELSE wal_sync_time / wal_sync
			END,
			0
		)::double precision
		FROM pg_stat_wal
	`).Scan(&latency)
	return latency, err
}

func (s *Server) latestAcceptedCount(ctx context.Context) (uint64, error) {
	if s == nil || s.pool == nil {
		return 0, errors.New("database pool not available")
	}
	var count uint64
	err := s.pool.QueryRow(ctx, `
		SELECT accepted_count
		FROM ingestion_stats
		ORDER BY stat_time DESC
		LIMIT 1
	`).Scan(&count)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return count, err
}

func (s *Server) deriveBatchSize(ctx context.Context) (float64, error) {
	current := metrics.EventsIngested()

	s.metricMu.Lock()
	haveBaseline := s.haveBatchBaseline
	last := s.lastEventsIngested
	if haveBaseline {
		s.lastEventsIngested = current
		s.metricMu.Unlock()
		if current >= last {
			return float64(current - last), nil
		}
		return 0, nil
	}
	s.metricMu.Unlock()

	initial := current
	if latest, err := s.latestAcceptedCount(ctx); err == nil && latest > 0 {
		initial = latest
	}

	s.metricMu.Lock()
	s.haveBatchBaseline = true
	s.lastEventsIngested = current
	s.metricMu.Unlock()
	return float64(initial), nil
}

func (s *Server) captureRuntimeMetrics(ctx context.Context) ([]metricSample, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("database pool not available")
	}

	s.metricMu.Lock()
	if !s.lastMetricSample.IsZero() && time.Since(s.lastMetricSample) < time.Second {
		s.metricMu.Unlock()
		return nil, nil
	}
	s.lastMetricSample = time.Now()
	s.metricMu.Unlock()

	tenantID, err := s.resolveMetricsTenantID(ctx)
	if err != nil {
		return nil, err
	}
	walLatency, err := s.queryWALFsyncLatency(ctx)
	if err != nil {
		return nil, err
	}
	batchSize, err := s.deriveBatchSize(ctx)
	if err != nil {
		return nil, err
	}

	queueDepth := 0.0
	if s.eventHub != nil {
		queueDepth = float64(s.eventHub.SubscriberQueueDepth())
	}
	breaker := 1.0
	if state := health.GetSystemState(); state != nil && state.IsOperational() {
		breaker = 0.0
	}

	now := time.Now().UTC()
	logicalClock := now.UnixMilli()
	samples := []metricSample{
		{Name: "wal_fsync_latency", Component: "postgres", Value: walLatency, RecordedAt: now, LogicalClock: logicalClock},
		{Name: "event_queue_depth", Component: "event_hub", Value: queueDepth, RecordedAt: now, LogicalClock: logicalClock},
		{Name: "batch_size", Component: "pipeline", Value: batchSize, RecordedAt: now, LogicalClock: logicalClock},
		{Name: "circuit_breaker_tripped", Component: "health", Value: breaker, RecordedAt: now, LogicalClock: logicalClock},
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	for _, sample := range samples {
		if _, err := tx.Exec(ctx, `
			INSERT INTO system_metrics (
				tenant_id,
				component,
				metric_name,
				metric_time,
				metric_value,
				metric_labels
			) VALUES ($1::uuid, $2::text, $3::text, $4::timestamptz, $5::double precision, $6::jsonb)
		`, tenantID, sample.Component, sample.Name, sample.RecordedAt, sample.Value, `{"source":"soc_runtime"}`); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	for _, sample := range samples {
		s.publishEnvelope(s.buildSystemMetricEnvelope(sample))
	}
	return samples, nil
}

func (s *Server) systemMetricLoop(ctx context.Context) {
	ticker := time.NewTicker(systemMetricInterval)
	defer ticker.Stop()

	_, _ = s.captureRuntimeMetrics(context.Background())

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = s.captureRuntimeMetrics(context.Background())
		}
	}
}

func (s *Server) telemetryLoop(ctx context.Context) {
	if s == nil || s.pool == nil || s.eventHub == nil {
		return
	}
	cursor := s.bootstrapTelemetryCursor(context.Background())
	ticker := time.NewTicker(telemetryPublishInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cursor = s.publishTelemetrySince(context.Background(), cursor)
		}
	}
}

func (s *Server) governanceLoop(ctx context.Context) {
	if s == nil || s.pool == nil || s.eventHub == nil {
		return
	}
	cursor := s.bootstrapGovernanceCursor(context.Background())
	ticker := time.NewTicker(governancePublishInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cursor = s.publishGovernanceSince(context.Background(), cursor)
		}
	}
}

func (s *Server) heartbeatLoop(ctx context.Context) {
	if s == nil || s.pool == nil || s.eventHub == nil {
		return
	}
	cursor := s.bootstrapHeartbeatCursor(context.Background())
	ticker := time.NewTicker(heartbeatPublishInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cursor = s.publishHeartbeatsSince(context.Background(), cursor)
		}
	}
}

func (s *Server) bootstrapTelemetryCursor(ctx context.Context) tailCursor {
	if s == nil || s.pool == nil {
		return tailCursor{}
	}
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()

	var cursor tailCursor
	if err := s.pool.QueryRow(ctx, `
		SELECT timestamp, event_id::text
		FROM telemetry_events
		ORDER BY timestamp DESC, event_id::text DESC
		LIMIT 1
	`).Scan(&cursor.Timestamp, &cursor.ID); err != nil {
		return tailCursor{}
	}
	return cursor
}

func (s *Server) bootstrapGovernanceCursor(ctx context.Context) tailCursor {
	if s == nil || s.pool == nil {
		return tailCursor{}
	}
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()

	var cursor tailCursor
	if err := s.pool.QueryRow(ctx, `
		SELECT created_at, audit_id::text
		FROM governance_audit_log
		ORDER BY created_at DESC, audit_id DESC
		LIMIT 1
	`).Scan(&cursor.Timestamp, &cursor.ID); err != nil {
		return tailCursor{}
	}
	return cursor
}

func (s *Server) bootstrapHeartbeatCursor(ctx context.Context) tailCursor {
	if s == nil || s.pool == nil {
		return tailCursor{}
	}
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()

	var cursor tailCursor
	if err := s.pool.QueryRow(ctx, `
		SELECT updated_at, agent_id::text
		FROM agent_sessions
		ORDER BY updated_at DESC, agent_id DESC
		LIMIT 1
	`).Scan(&cursor.Timestamp, &cursor.ID); err != nil {
		return tailCursor{}
	}
	return cursor
}

func (s *Server) publishTelemetrySince(ctx context.Context, cursor tailCursor) tailCursor {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()

	query := `
		SELECT event_id::text,
		       COALESCE(agent_id::text, ''),
		       event_type,
		       source_type,
		       logical_clock,
		       timestamp,
		       COALESCE(encode(payload_sha256, 'hex'), '')
		FROM telemetry_events
	`
	args := []any{maxTailBatch}
	if !cursor.Timestamp.IsZero() && cursor.ID != "" {
		query += `
		WHERE timestamp > $1
		   OR (timestamp = $1 AND event_id::text > $2)
		ORDER BY timestamp ASC, event_id::text ASC
		LIMIT $3
	`
		args = []any{cursor.Timestamp, cursor.ID, maxTailBatch}
	} else {
		query += `
		WHERE timestamp > $1
		ORDER BY timestamp ASC, event_id::text ASC
		LIMIT $2
	`
		args = []any{cursor.Timestamp, maxTailBatch}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return cursor
	}
	defer rows.Close()

	for rows.Next() {
		var eventID string
		var identity string
		var eventType string
		var sourceType string
		var hashHex string
		var logicalClock int64
		var ts time.Time
		if err := rows.Scan(
			&eventID,
			&identity,
			&eventType,
			&sourceType,
			&logicalClock,
			&ts,
			&hashHex,
		); err != nil {
			continue
		}
		row := TelemetryRow{
			EventID:              eventID,
			EventType:            eventType,
			SourceType:           sourceType,
			Timestamp:            ts.UTC().Format(time.RFC3339Nano),
			LogicalClock:         logicalClock,
			CanonicalPayloadHash: hashHex,
		}
		row.AgentID, row.ProbeID = telemetryIdentityFields(sourceType, identity)
		if err := validateTelemetryRow(row); err != nil {
			log.Printf("SOC_TELEMETRY_REJECT event_id=%s err=%v", eventID, err)
			continue
		}
		cursor = tailCursor{Timestamp: ts.UTC(), ID: eventID}
		s.publishEnvelope(s.buildTelemetryEnvelope(eventID, identity, eventType, sourceType, hashHex, logicalClock, ts))
	}
	return cursor
}

func (s *Server) publishGovernanceSince(ctx context.Context, cursor tailCursor) tailCursor {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT audit_id::text,
		       tenant_id::text,
		       event_type,
		       actor,
		       COALESCE(details_json, '{}'::jsonb),
		       COALESCE(signature_hex, ''),
		       created_at
		FROM governance_audit_log
		WHERE created_at > $1
		   OR (created_at = $1 AND audit_id::text > $2)
		ORDER BY created_at ASC, audit_id ASC
		LIMIT $3
	`, cursor.Timestamp, cursor.ID, maxTailBatch)
	if err != nil {
		return cursor
	}
	defer rows.Close()

	for rows.Next() {
		var auditID, tenantID, eventType, actorID, sigHex string
		var detailsRaw []byte
		var createdAt time.Time
		if err := rows.Scan(&auditID, &tenantID, &eventType, &actorID, &detailsRaw, &sigHex, &createdAt); err != nil {
			continue
		}
		cursor = tailCursor{Timestamp: createdAt, ID: auditID}
		signatureValid := verifyGovernanceSignature(tenantID, eventType, actorID, createdAt, detailsRaw, sigHex)
		s.publishEnvelope(s.buildGovernanceEnvelope(auditID, tenantID, eventType, actorID, signatureValid, createdAt))
	}
	return cursor
}

func (s *Server) publishHeartbeatsSince(ctx context.Context, cursor tailCursor) tailCursor {
	ctx, cancel := context.WithTimeout(ctx, dbQueryTimeout)
	defer cancel()

	rows, err := s.pool.Query(ctx, `
		SELECT agent_id::text,
		       hostname,
		       status,
		       lamport_clock,
		       last_heartbeat,
		       updated_at
		FROM agent_sessions
		WHERE updated_at > $1
		   OR (updated_at = $1 AND agent_id::text > $2)
		ORDER BY updated_at ASC, agent_id ASC
		LIMIT $3
	`, cursor.Timestamp, cursor.ID, maxTailBatch)
	if err != nil {
		return cursor
	}
	defer rows.Close()

	for rows.Next() {
		var agentID, hostname, status string
		var logicalClock int64
		var heartbeatAt, updatedAt time.Time
		if err := rows.Scan(&agentID, &hostname, &status, &logicalClock, &heartbeatAt, &updatedAt); err != nil {
			continue
		}
		cursor = tailCursor{Timestamp: updatedAt, ID: agentID}
		s.publishEnvelope(s.buildHeartbeatEnvelope(agentID, hostname, status, logicalClock, heartbeatAt))
	}
	return cursor
}
