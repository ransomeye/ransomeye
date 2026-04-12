package pipeline

import (
	"encoding/json"
	"time"
)

type canonicalDetectionPayload struct {
	Seq             int64                   `json:"seq"`
	Type            string                  `json:"type"`
	EventID         string                  `json:"event_id"`
	AgentID         string                  `json:"agent_id"`
	Action          string                  `json:"action"`
	Target          string                  `json:"target"`
	Status          string                  `json:"status"`
	Timestamp       int64                   `json:"timestamp"`
	LogicalClock    int64                   `json:"logical_clock"`
	Score           float64                 `json:"score"`
	Decision        string                  `json:"decision"`
	ModelPrediction float64                 `json:"model_prediction"`
	EntropyScore    float64                 `json:"entropy_score"`
	BurstScore      float64                 `json:"burst_score"`
	ProcessAnomaly  float64                 `json:"process_anomaly"`
	Explanation     []detectionContribution `json:"explanation"`
}

type detectionContribution struct {
	Feature string  `json:"feature"`
	Impact  float64 `json:"impact"`
	Value   float64 `json:"value"`
}

func GetDetectionEventEnvelope(seq int64, eventID string, agentID string, ts time.Time, finding DetectionEvent, logicalClock int64) *EventEnvelope {
	env := envelopePool.Get().(*EventEnvelope)
	env.refCount.Store(1)
	env.Seq = seq
	env.Type = "detection"
	env.EventID = eventID
	env.AgentID = agentID
	env.Action = "detection"
	env.Target = eventID
	env.Status = finding.Decision
	env.Timestamp = ts.UTC()
	env.Priority = PriorityCritical

	explanation := make([]detectionContribution, 0, len(finding.Explanation))
	for _, item := range finding.Explanation {
		explanation = append(explanation, detectionContribution{
			Feature: item.Feature,
			Impact:  item.Impact,
			Value:   item.Value,
		})
	}
	payload := canonicalDetectionPayload{
		Seq:             seq,
		Type:            env.Type,
		EventID:         eventID,
		AgentID:         agentID,
		Action:          env.Action,
		Target:          env.Target,
		Status:          env.Status,
		Timestamp:       env.Timestamp.Unix(),
		LogicalClock:    logicalClock,
		Score:           finding.Confidence,
		Decision:        finding.Decision,
		ModelPrediction: finding.ModelPrediction,
		EntropyScore:    finding.EntropyScore,
		BurstScore:      finding.BurstScore,
		ProcessAnomaly:  finding.ProcessAnomaly,
		Explanation:     explanation,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		raw = []byte(`{"seq":0,"type":"error","event_id":"","agent_id":"","action":"","target":"","status":"marshal_error","timestamp":0,"score":0,"decision":"error","model_prediction":0,"entropy_score":0,"burst_score":0,"process_anomaly":0,"explanation":[]}`)
	}
	env.Payload = raw
	return env
}
