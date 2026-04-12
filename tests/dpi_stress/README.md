# DPI stress validation (PRD-06)

This harness measures **DPI drop ratio** (parts-per-million from core metrics), **control-plane latency**, and **host CPU** while replaying a minimal PCAP at increasing rates.

**Why `dpi_packets_total` used to stay ~16:** the DPI engine only emits signed events when L7 payload matches static signatures (`GET /`, `POST /`, `SSH-2.0-`, …). A bare TCP SYN has **no L7 bytes**, so the probe forwards almost nothing and Core metrics barely move — and `dpi_drop_ratio` looks “stuck” at zero. `gen_min_pcap.py` now embeds a minimal **HTTP GET** in a TCP segment so each replayed frame can produce a real event (PRD-06 validation path).

## Prerequisites

- `tcpreplay` (packet replay)
- `curl`, `jq`
- Root or `CAP_NET_RAW` for injection on a real NIC (loopback replay is **best-effort** and may not exercise the same XDP/AF_PACKET path as 10GbE).

## Usage

```bash
sudo ./run_stress.sh -i eth0 -p sample.pcap
```

Environment:

| Variable | Default | Description |
|----------|---------|-------------|
| `SOC_URL` | `http://127.0.0.1:8443` | Core SOC HTTP (ingestion metrics) |
| `RAMP` | `1000,5000,10000` | Target rates in Mbps (comma-separated) |
| `SAMPLE_MS` | `8000` | Sample window per step |

## Pass / fail (enterprise gate)

- **FAIL** if `dpi_drop_ratio` > **1000 ppm** (0.1%) at any step.
- **FAIL** if `dpi_control_latency` regresses beyond the step-0 baseline by > **10×** (latency spike heuristic).
- **WARN** if `tcpreplay` reports send errors (ring pressure).

## Hardware-saturated runs

On a lab host with a dedicated 10GbE port, replace `-i lo` with that interface and use a representative PCAP (mixed TCP/UDP). Archive `results/run-*.json` for audit.
