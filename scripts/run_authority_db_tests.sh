#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_HELPER="${SCRIPT_DIR}/authority_db_env.sh"

usage() {
  cat <<'EOF'
Usage:
  scripts/run_authority_db_tests.sh check
  scripts/run_authority_db_tests.sh prepare
  scripts/run_authority_db_tests.sh gateway
  scripts/run_authority_db_tests.sh authority
  scripts/run_authority_db_tests.sh pipeline
  scripts/run_authority_db_tests.sh all

Commands:
  check      Validate local DB listener, TLS, and auth; print no test output.
  prepare    Validate DB access and apply pending core/migrations via psql helper.
  gateway    Run DB-backed gateway replay/authority tests.
  authority  Run authority-focused proof tests (DB-backed where available).
  pipeline   Run pipeline hot-path authority integration proof.
  all        Run gateway + authority + pipeline in sequence after DB check.
EOF
}

require_env() {
  eval "$("${ENV_HELPER}" --export)"
  # Operator core.env may pin execution context for the running core; gateway e2e instead
  # derives context from per-test PRD13 JSON env. Leaving the global hash set breaks SendSignal tests.
  unset RANSOMEYE_EXECUTION_CONTEXT_HASH || true
}

run_check() {
  "${ENV_HELPER}" --check
}

prepare_db() {
  require_env
  run_check
  echo "[authority-db] applying numbered core migrations with psql helper"
  "${SCRIPT_DIR}/slice1_apply_migrations_psql.sh"
}

run_gateway() {
  require_env
  run_check
  cd "${REPO_ROOT}"
  go test -count=1 -v ./core/internal/gateway -run 'TestSendSignal_DB_E2E|TestLastCommittedReplayCursor'
}

run_authority() {
  require_env
  run_check
  cd "${REPO_ROOT}"
  go test -count=1 -v ./core/internal/storage/authority -run 'TestSchemaTransformHash_Deterministic|TestDeterministicBatchCommitID_Stable|TestValidateExecutionContextUniformBatch|TestVerifyCommittedBatch_FailsOnExecutionContextMismatchInRange|TestCommitPartitionBatch_FailsClosedOnMissingTrustSnapshotBinding|TestCommitPartitionBatch_FailsClosedOnAmbiguousTrustSnapshotBindings|TestCommitPartitionBatch_FailsClosedOnDuplicateLogicalBindings'
}

run_pipeline() {
  require_env
  run_check
  cd "${REPO_ROOT}"
  go test -count=1 -v ./core/internal/pipeline -run 'TestPRD13CommitWiredIntoPersistenceHotPath'
}

run_all() {
  require_env
  run_check
  cd "${REPO_ROOT}"
  # Authority integration seeds fixed record_id values; run before gateway so gateway
  # SIGNAL commits cannot collide on UNIQUE(record_type, record_id) with leftover seed rows.
  go test -count=1 -v ./core/internal/storage/authority -run 'TestSchemaTransformHash_Deterministic|TestDeterministicBatchCommitID_Stable|TestValidateExecutionContextUniformBatch|TestVerifyCommittedBatch_FailsOnExecutionContextMismatchInRange|TestCommitPartitionBatch_FailsClosedOnMissingTrustSnapshotBinding|TestCommitPartitionBatch_FailsClosedOnAmbiguousTrustSnapshotBindings|TestCommitPartitionBatch_FailsClosedOnDuplicateLogicalBindings'
  go test -count=1 -v ./core/internal/gateway -run 'TestSendSignal_DB_E2E|TestLastCommittedReplayCursor'
  go test -count=1 -v ./core/internal/pipeline -run 'TestPRD13CommitWiredIntoPersistenceHotPath'
}

main() {
  if [[ $# -ne 1 ]]; then
    usage >&2
    exit 2
  fi
  case "$1" in
    check)
      run_check
      ;;
    prepare)
      prepare_db
      ;;
    gateway)
      run_gateway
      ;;
    authority)
      run_authority
      ;;
    pipeline)
      run_pipeline
      ;;
    all)
      run_all
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
