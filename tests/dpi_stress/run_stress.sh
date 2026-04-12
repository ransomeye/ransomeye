#!/usr/bin/env bash
# DPI ingress hardening: expected PACKETS_IN delta vs tcpreplay replay × loopback factor (±5%),
# strict monotonic deltas vs Mbps (via scaled --loop). Requires root.
# Usage: sudo ./run_stress.sh [mbps1 mbps2 ...]   (default: 1000 10000 50000)
# Phase 3 (DBS): e.g. sudo ./run_stress.sh 100000 200000 — enables bounded egress queue + drain delay.
set -euo pipefail

# sudo often strips cargo from PATH; keep rustup + system dirs for optional auto-build.
export PATH="${PATH}:/usr/local/bin:/usr/bin:${HOME}/.cargo/bin"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [[ -f "${REPO_ROOT}/scripts/reproducible-build-env.sh" ]]; then
	# shellcheck disable=SC1090
	source "${REPO_ROOT}/scripts/reproducible-build-env.sh" "${REPO_ROOT}"
fi
DPI_CRATE="$REPO_ROOT/dpi-probe"
DPI_BIN="${DPI_BIN:-${CARGO_TARGET_DIR:-${REPO_ROOT}/dpi-probe/target}/release/dpi-ingest-validate}"
PCAP="${PCAP:-$SCRIPT_DIR/sample.pcap}"
IFACE="${IFACE:-lo}"
SAMPLE_SEC="${SAMPLE_SEC:-6}"
RESULT_DIR="$SCRIPT_DIR/results"
LOG="$RESULT_DIR/ingest-validate.log"
TCPP_OUT="$RESULT_DIR/tcpreplay-last.txt"

need() { command -v "$1" >/dev/null 2>&1; }

if [[ $# -ge 1 ]]; then
  LOADS=("$@")
else
  LOADS=(1000 10000 50000)
fi

if [[ "${EUID:-0}" -ne 0 ]]; then
  echo "run as root (CAP_NET_RAW for AF_PACKET + tcpreplay on $IFACE)" >&2
  exit 2
fi

mkdir -p "$RESULT_DIR"
rm -f "$LOG" "$TCPP_OUT"

if ! need python3; then
  echo "missing python3" >&2
  exit 2
fi

if ! need tcpreplay || ! need timeout; then
  echo '{"status":"SKIP","reason":"tcpreplay or timeout missing"}' | tee "$RESULT_DIR/skip.json"
  exit 0
fi

pcap_frame_count() {
  python3 - "$1" <<'PY'
import struct, sys
path = sys.argv[1]
try:
    with open(path, "rb") as f:
        d = f.read()
except OSError:
    print(0)
    raise SystemExit(0)
if len(d) < 24 or struct.unpack_from("<I", d, 0)[0] != 0xA1B2C3D4:
    print(0)
    raise SystemExit(0)
off = 24
n = 0
while off + 16 <= len(d):
    incl = struct.unpack_from("<I", d, off + 8)[0]
    off += 16 + incl
    n += 1
print(n)
PY
}

if [[ ! -f "$PCAP" ]] || [[ "$(pcap_frame_count "$PCAP")" -lt 10000 ]]; then
  echo "generating $PCAP (>=10000 frames)" >&2
  python3 "$SCRIPT_DIR/gen_min_pcap.py" "$PCAP"
fi

FRAME_COUNT="$(pcap_frame_count "$PCAP")"

if [[ ! -x "$DPI_BIN" ]]; then
  if ! command -v cargo >/dev/null 2>&1; then
    echo "missing dpi-ingest-validate at $DPI_BIN and cargo not on PATH (pre-build or export PATH)" >&2
    exit 2
  fi
  echo "building dpi-ingest-validate (release)…" >&2
  (cd "$DPI_CRATE" && cargo build --release --bin dpi-ingest-validate)
fi

packets_in_last() {
  grep '\[DPI\] packets_in=' "$LOG" 2>/dev/null | tail -1 | sed -n 's/.*packets_in=\([0-9][0-9]*\).*/\1/p' || echo "0"
}

# loop_factor: loopback often duplicates (RX+TX) on the same capture.
if [[ "$IFACE" == "lo" ]]; then
  LOOP_FACTOR=2
else
  LOOP_FACTOR=1
fi

min_mbps="${LOADS[0]}"
for m in "${LOADS[@]}"; do
  [[ "$m" -lt "$min_mbps" ]] && min_mbps=$m
done

_stress_dbs=0
for m in "${LOADS[@]}"; do
  if [[ "$m" -ge 100000 ]]; then
    _stress_dbs=1
    break
  fi
done

# Wall-clock budget for the full script so dpi-ingest-validate exits cleanly and writes
# `[DPI] pas FINAL …` (same counters + invariant) before we parse the log.
_stress_est_sec=$(( 10 + ${#LOADS[@]} * (SAMPLE_SEC + 2) + 60 ))

export RANSOMEYE_DPI_BACKEND="${RANSOMEYE_DPI_BACKEND:-af_packet}"
export RANSOMEYE_DPI_INTERFACE="$IFACE"
export RANSOMEYE_DPI_INGEST_LOG_INTERVAL_MS="${RANSOMEYE_DPI_INGEST_LOG_INTERVAL_MS:-1000}"
export RANSOMEYE_DPI_INGEST_VALIDATE_MAX_MS="${RANSOMEYE_DPI_INGEST_VALIDATE_MAX_MS:-$((_stress_est_sec * 1000))}"
# Do not enable STALL_FATAL here: idle gaps between replay steps would panic the stats thread.
if [[ "$_stress_dbs" -eq 1 ]]; then
  export RANSOMEYE_DPI_EGRESS_QUEUE_DEPTH="${RANSOMEYE_DPI_EGRESS_QUEUE_DEPTH:-256}"
  export RANSOMEYE_DPI_EGRESS_DRAIN_DELAY_US="${RANSOMEYE_DPI_EGRESS_DRAIN_DELAY_US:-15}"
  echo "[VALIDATION] Phase3 DBS: egress bounded queue depth=${RANSOMEYE_DPI_EGRESS_QUEUE_DEPTH} drain_delay_us=${RANSOMEYE_DPI_EGRESS_DRAIN_DELAY_US}" >&2
fi

"$DPI_BIN" >>"$LOG" 2>&1 &
DPI_PID=$!

cleanup() {
  if [[ -n "${DPI_PID:-}" ]]; then
    kill "$DPI_PID" 2>/dev/null || true
    wait "$DPI_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

for _ in $(seq 1 50); do
  if grep -q '\[DPI\] packets_in=' "$LOG" 2>/dev/null; then
    break
  fi
  sleep 0.2
done

if ! grep -q '\[DPI\] packets_in=' "$LOG" 2>/dev/null; then
  echo "FAIL: no [DPI] packets_in= lines from dpi-ingest-validate" >&2
  exit 1
fi

declare -a DELTAS=()
declare -a MBPS_ARR=()
declare -a EXPECTED_ARR=()
declare -a REPLAY_ARR=()
declare -a DEVPCT_ARR=()
declare -a DROPPED_SNAPS=()
declare -a QFULL_SNAPS=()
fail=0

for mbps in "${LOADS[@]}"; do
  loop_n=$((mbps / min_mbps))
  [[ "$loop_n" -lt 1 ]] && loop_n=1
  echo "=== tcpreplay -M ${mbps} Mbps loop=${loop_n} (${SAMPLE_SEC}s cap) ===" >&2
  echo "[VALIDATION] pcap_frames=${FRAME_COUNT} loop_n=${loop_n} loop_factor=${LOOP_FACTOR} (iface=${IFACE})" >&2

  before="$(packets_in_last)"
  rm -f "$TCPP_OUT"
  set +e
  timeout --signal=INT --preserve-status "$SAMPLE_SEC" \
    tcpreplay -i "$IFACE" -M "$mbps" --loop="$loop_n" "$PCAP" >"$TCPP_OUT" 2>&1
  set -e
  sleep 2
  after="$(packets_in_last)"
  delta=$((after - before))

  replay_count=""
  if grep -qE 'Successful packets:' "$TCPP_OUT"; then
    replay_count="$(sed -n 's/.*Successful packets:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$TCPP_OUT" | tail -1)"
  fi
  if [[ -z "$replay_count" ]] && grep -qE 'Actual:[[:space:]]*[0-9]+[[:space:]]+packets' "$TCPP_OUT"; then
    replay_count="$(sed -n 's/.*Actual:[[:space:]]*\([0-9][0-9]*\)[[:space:]]\+packets.*/\1/p' "$TCPP_OUT" | tail -1)"
  fi
  if [[ -z "$replay_count" ]]; then
    echo "FAIL: could not parse tcpreplay replay count from output" >&2
    fail=1
    replay_count=0
  fi

  expected=$((replay_count * LOOP_FACTOR))

  read -r dev_ok dev_pct <<< "$(python3 - "$delta" "$expected" <<'PY'
import sys
obs = int(sys.argv[1])
exp = int(sys.argv[2])
if exp <= 0:
    print("0 nan")
    raise SystemExit(0)
dev = abs(obs - exp) / float(exp)
print("1" if dev < 0.05 else "0", f"{dev * 100.0:.4f}")
PY
)"

  echo "[VALIDATION] replay_count=${replay_count} expected_packets=${expected} observed_delta=${delta} deviation_pct=${dev_pct}" >&2

  MBPS_ARR+=("$mbps")
  DELTAS+=("$delta")
  EXPECTED_ARR+=("$expected")
  REPLAY_ARR+=("$replay_count")
  DEVPCT_ARR+=("$dev_pct")

  echo "[DPI] step mbps=$mbps loop_n=$loop_n packets_in_delta=$delta expected=$expected deviation_pct=${dev_pct}" | tee -a "$LOG"

  if [[ "$delta" -le 0 ]]; then
    echo "FAIL: packets_in did not increase at ${mbps} Mbps" >&2
    fail=1
  fi
  if [[ "$dev_ok" != "1" ]]; then
    echo "FAIL: |obs-expected|/expected >= 5% (obs=$delta expected=$expected)" >&2
    fail=1
  fi

  _pas_tail="$(grep '\[DPI\] pas ' "$LOG" 2>/dev/null | tail -1 || true)"
  _d_snap="$(printf '%s' "$_pas_tail" | sed -n 's/.*dropped=\([0-9][0-9]*\).*/\1/p')"
  _q_snap="$(printf '%s' "$_pas_tail" | sed -n 's/.*qfull=\([0-9][0-9]*\).*/\1/p')"
  [[ -z "$_d_snap" ]] && _d_snap="0"
  [[ -z "$_q_snap" ]] && _q_snap="0"
  DROPPED_SNAPS+=("$_d_snap")
  QFULL_SNAPS+=("$_q_snap")
done

for i in $(seq 1 $((${#DELTAS[@]} - 1))); do
  j=$((i - 1))
  if [[ "${DELTAS[$i]}" -le "${DELTAS[$j]}" ]]; then
    echo "FAIL: PACKETS_IN delta must strictly increase with load (${MBPS_ARR[$j]} -> ${MBPS_ARR[$i]}): ${DELTAS[$j]} -> ${DELTAS[$i]}" >&2
    fail=1
  fi
done

if [[ "$_stress_dbs" -eq 1 ]] && [[ "$fail" -eq 0 ]]; then
  for i in $(seq 1 $((${#DROPPED_SNAPS[@]} - 1))); do
    j=$((i - 1))
    if [[ "${DROPPED_SNAPS[$i]}" -lt "${DROPPED_SNAPS[$j]}" ]]; then
      echo "FAIL: DBS dropped= must not decrease with load (${MBPS_ARR[$j]} -> ${MBPS_ARR[$i]}): ${DROPPED_SNAPS[$j]} -> ${DROPPED_SNAPS[$i]}" >&2
      fail=1
    fi
  done
  _last_d="${DROPPED_SNAPS[$(( ${#DROPPED_SNAPS[@]} - 1 ))]}"
  _last_q="${QFULL_SNAPS[$(( ${#QFULL_SNAPS[@]} - 1 ))]}"
  if [[ "$_last_d" -eq 0 ]] && [[ "$_last_q" -eq 0 ]]; then
    echo "FAIL: Phase3 DBS expected queue pressure (qfull>0) or drops (dropped>0) at high load" >&2
    fail=1
  fi
fi

if [[ "$fail" -eq 0 ]]; then
  echo "[VALIDATION] waiting for dpi-ingest-validate exit (FINAL pas + invariant)…" >&2
  wait "$DPI_PID" 2>/dev/null || true
  DPI_PID=""
fi

pas_line="$(grep '\[DPI\] pas ' "$LOG" 2>/dev/null | tail -1 || true)"
if [[ -z "$pas_line" ]]; then
  echo "FAIL: no [DPI] pas line in log (PAS accounting / stats logger)" >&2
  fail=1
else
  echo "[VALIDATION] pas_snapshot: $pas_line" >&2
  if ! python3 - "$pas_line" <<'PY'
import re, sys
line = sys.argv[1]
m = re.search(
    r"in=(\d+)\s+parsed=(\d+)\s+processed=(\d+)\s+dropped=(\d+)\s+failed=(\d+)\s+sum_out=(\d+)",
    line,
)
if not m:
    sys.stderr.write(f"FAIL: could not parse PAS line: {line!r}\n")
    sys.exit(1)
in_c, _parsed, proc, drp, failed, sum_o = map(int, m.groups())
out_sum = proc + drp + failed
if in_c != out_sum:
    sys.stderr.write(
        f"FAIL: assert in == processed+dropped+failed: in={in_c} processed={proc} dropped={drp} failed={failed} sum={out_sum}\n"
    )
    sys.exit(1)
if in_c != sum_o:
    sys.stderr.write(f"FAIL: sum_out mismatch in={in_c} sum_out={sum_o}\n")
    sys.exit(1)
sys.stderr.write(f"PASS PAS invariant in={in_c} == processed+dropped+failed\n")
PY
  then
    fail=1
  fi
fi

if ! grep -q '\[DPI\] pas FINAL' "$LOG" 2>/dev/null; then
  echo "FAIL: no [DPI] pas FINAL line in log (graceful shutdown snapshot)" >&2
  fail=1
fi

ts="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$RESULT_DIR/run-ingest-${ts}.json"
_comma_loads=$(printf ',%s' "${MBPS_ARR[@]}")
_comma_deltas=$(printf ',%s' "${DELTAS[@]}")
_comma_exp=$(printf ',%s' "${EXPECTED_ARR[@]}")
_comma_rep=$(printf ',%s' "${REPLAY_ARR[@]}")
_comma_dev=$(printf ',%s' "${DEVPCT_ARR[@]}")
_comma_drop=$(IFS=,; echo "${DROPPED_SNAPS[*]}")
_comma_qfull=$(IFS=,; echo "${QFULL_SNAPS[*]}")
{
  echo "{"
  echo "  \"status\": \"$([[ "$fail" -eq 0 ]] && echo PASS || echo FAIL)\","
  echo "  \"interface\": \"$IFACE\","
  echo "  \"loop_factor\": $LOOP_FACTOR,"
  echo "  \"pcap\": \"$PCAP\","
  echo "  \"pcap_frames\": $FRAME_COUNT,"
  echo "  \"sample_sec\": $SAMPLE_SEC,"
  echo "  \"loads_mbps\": [${_comma_loads:1}],"
  echo "  \"replay_counts\": [${_comma_rep:1}],"
  echo "  \"expected_packets_in_delta\": [${_comma_exp:1}],"
  echo "  \"packets_in_deltas\": [${_comma_deltas:1}],"
  echo "  \"deviation_pct\": [${_comma_dev:1}],"
  echo "  \"phase3_dbs\": ${_stress_dbs},"
  echo "  \"pas_dropped_snaps\": [${_comma_drop}],"
  echo "  \"pas_qfull_snaps\": [${_comma_qfull}]"
  echo "}"
} | tee "$OUT"

[[ "$fail" -eq 0 ]]
