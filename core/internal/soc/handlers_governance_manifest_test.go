package soc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleSocGovernanceManifest(t *testing.T) {
	srv := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/soc/governance-manifest", nil)
	srv.handleSocGovernanceManifest(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v", err)
	}
	if body["manifest_version"] == nil {
		t.Fatal("missing manifest_version")
	}
	p21, ok := body["prd_21_ui_governance"].(map[string]any)
	if !ok {
		t.Fatal("missing prd_21_ui_governance object")
	}
	if p21["role"] == nil {
		t.Fatal("missing prd_21 role")
	}
	p22, ok := body["prd_22_shadow_intelligence"].(map[string]any)
	if !ok || p22["cannot_trigger_enforcement"] != true {
		t.Fatalf("prd_22 shadow safety fields: %#v", p22)
	}
}
