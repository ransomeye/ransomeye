# Mishka Slice 4 — SOC UI, shadow, assets, dashboards (honesty)

## PRD mapping

| PRD | What shipped |
|-----|----------------|
| **PRD-21** | `GET /api/v1/soc/governance-manifest` (static interaction boundaries). Global `PresentationLawBanner` in UI. Governance page embeds manifest JSON. Write surfaces remain incidents only (intent). |
| **PRD-22** | Dedicated route + UI **Shadow intelligence** with advisory styling; API flags `opaif_safe_surface`, `cannot_trigger_enforcement`, `cannot_influence_priority`. |
| **PRD-23** | **Asset coverage** page + `ui_lineage` on `GET /api/v1/assets/coverage` (SQL basis, no CMDB claim, no partition_records join). Fleet page shows structured agents + `ui_lineage`. |
| **PRD-25** | Operator dashboard labeled; **Executive summary** as subordinate projection; `ui_lineage` on list/compliance/fleet/explainability responses where applicable. |
| **PRD-15** | Declared in manifest; LOO API documents working-set scope + deterministic sort. |
| **PRD-13 subordination** | Explicit `not_query_record_v1` / `not_report_record_v1` on aggregates — no fake committed query/report objects. |

## Verification

```bash
go test ./core/internal/soc/... -count=1 -timeout 90s
cd ui && npm ci && npm run build
```

Live curl (after deploy):

```bash
curl -sS http://127.0.0.1:8080/api/v1/soc/governance-manifest | jq .
curl -sS http://127.0.0.1:8080/api/v1/assets/coverage | jq .ui_lineage
```

(Adjust host/port to your nginx/core bind.)

## Remaining honest gaps

- No `query_record_v1` / `query_result_record_v1` / `report_record_v1` persistence or UI binding yet (Phase 2 per PRD-25 table).
- Detection **recent** array response unchanged for backward compatibility (no `ui_lineage` wrapper).
- WebSocket / client caches remain ephemeral (non-authoritative).

## Runtime hygiene (host acceptance)

For any slice that touches deploy/runtime, follow **`docs/validation/mishka_runtime_hygiene.md`**: `ss -tlnp`, `systemctl list-units 'ransomeye*'`, classify listeners, remove legacy stacks **without** rebinding Mishka ports. Old `/stream` branding on `https://localhost/...` with a single nginx:443 listener usually means **stale `/opt/ransomeye/ui/dist`** — redeploy UI build, not a new port.
