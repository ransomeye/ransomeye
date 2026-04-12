# DPI stress — sample outputs

## tcpreplay missing (CI / minimal host)

```json
{"status":"SKIP","reason":"tcpreplay not installed"}
```

## Successful lab run (shape)

After `sudo ./run_stress.sh -i eth3 -p ./capture.pcap` with Core SOC reachable:

```json
{
  "status": "PASS",
  "started_utc": "2026-03-23T12:00:00Z",
  "interface": "eth3",
  "pcap": "./capture.pcap",
  "baseline": { "dpi_drop_ratio_ppm": 12, "dpi_control_latency_us": 140 },
  "steps": [
    { "mbps": 1000, "dpi_drop_ratio_ppm": 50, "dpi_control_latency_us": 160, "step_fail": 0 },
    { "mbps": 5000, "dpi_drop_ratio_ppm": 120, "dpi_control_latency_us": 200, "step_fail": 0 },
    { "mbps": 10000, "dpi_drop_ratio_ppm": 800, "dpi_control_latency_us": 260, "step_fail": 0 }
  ]
}
```

Fail if any `dpi_drop_ratio_ppm` > **1000** (0.1%) or latency spikes **10×** baseline.
