```text id="docx1"
MISHKA-INFRA-02 — Production Cluster Topology & Deployment Architecture
```

```text id="docx2"
DEPLOYMENT SPECIFICATION (NON-AUTHORITATIVE)
DERIVED FROM:
- PRD-24
- MISHKA-EXEC-01
- MISHKA-DEPLOY-01
```

---

# 🔴 SECTION 1 — GLOBAL SCALE INPUT

```text id="s1"
AGENTS: 1,000,000
AVG SIGNAL RATE: 2/sec
PEAK BURST: 5x
SIGNAL SIZE: 1 KB
```

Derived:

```text id="s1d"
AVG: 2M signals/sec
PEAK: 10M signals/sec
```

---

# 🔴 SECTION 2 — KAFKA CLUSTER TOPOLOGY

## 2.1 CLUSTER SHAPE

```text id="k1"
BROKERS: 36
REPLICATION FACTOR: 3
MIN_ISR: 2
ACKS: ALL
```

---

## 2.2 RACK DISTRIBUTION

```text id="k2"
3 AZs
12 brokers per AZ
rack-aware partition placement
```

---

## 2.3 PARTITIONS

```text id="k3"
signal_ingest_log: 2000 partitions
All other topic partition counts MUST match the exact derived values in MISHKA-DEPLOY-01 `SECTION 3. TOPIC CONFIG (EXACT)`.
```

---

## 2.4 NETWORK

```text id="k4"
INTERNAL BANDWIDTH PER BROKER: ≥ 25 Gbps
CLUSTER BACKPLANE: ≥ 200 Gbps aggregate
```

---

# 🔴 SECTION 3 — SERVICE DEPLOYMENT (KUBERNETES)

## 3.1 CLUSTER

```text id="k8s1"
Kubernetes multi-AZ cluster
Node count: 120 nodes
Node type: 16 vCPU / 64 GB RAM

NON-AUTHORITATIVE DERIVED NOTE:
Service instance counts below are logical fleet sizing projections derived from MISHKA-DEPLOY-01.
They MUST NOT be read as a literal simultaneous pod guarantee on this single cluster shape.
```

---

## 3.2 SERVICE DISTRIBUTION

## INGEST_GATEWAY

```text
instances: 200
CPU: 32 cores
RAM: 128 GiB
```

---

## REPLAY_GUARD

```text
instances: 256
CPU: 32 cores
RAM: 128 GiB
```

---

## PARTITION_ROUTER

```text
instances: 128
CPU: 32 cores
RAM: 128 GiB
```

---

## DECISION_ENGINE

```text
instances: 1024
CPU: 32 cores
RAM: 128 GiB
```

---

## POLICY_ENGINE

```text
instances: 512
CPU: 32 cores
RAM: 128 GiB
```

---

## ENFORCEMENT_ENGINE

```text
instances: 512
CPU: 32 cores
RAM: 128 GiB
```

---

## STORAGE_WRITER (CRITICAL)

```text
instances: 2000
CPU: 16 cores
RAM: 64 GiB
```

---

## REPLAY_ENGINE

```text
instances: 64
CPU: 32 cores
RAM: 256 GiB
```

---

# 🔴 SECTION 4 — STORAGE CLUSTER (PRD-13)

## 4.1 NODE CONFIG

```text id="st1"
storage nodes: deployment_profile.storage_node_count
disk per node: deployment_profile.usable_bytes_per_storage_node
type: NVMe + HDD hybrid
```

---

## 4.2 TIERS

```text id="st2"
HOT (7d): NVMe
WARM (30d): HDD
ARCHIVAL (365d): object storage
```

---

## 4.3 THROUGHPUT

```text id="st3"
write throughput: MUST satisfy derived peak_hot_write_throughput from DEPLOY-01
IOPS: MUST satisfy derived peak storage IOPS from DEPLOY-01
```

---

# 🔴 SECTION 5 — NETWORK TOPOLOGY

```text id="net1"
Edge → Ingest: public ingress (TLS)
Ingest → Kafka: internal VPC
Kafka → Services: internal VPC
Storage → Replay: internal only
```

---

# 🔴 SECTION 6 — BACKPRESSURE PROPAGATION (PHYSICAL)

```text id="bp1"
Storage saturation → Kafka lag → Ingest throttle → Edge escrow
```

Thresholds:

```text id="bp2"
Kafka lag:
- warning: 100k msgs/partition
- critical: 500k
- halt: 1M

Storage:
- warning: 80%
- critical: 90%
- halt: 95%
- EMERGENCY_RESERVE: 5% (aligned with MISHKA-DEPLOY-01)
```

---

# 🔴 SECTION 7 — FAILURE TOLERANCE

```text id="ft1"
Kafka:
- tolerate 1 AZ loss
- tolerate 12 broker loss

Storage:
- tolerate 1 AZ loss
- replication across AZs

K8s:
- pod auto-reschedule within 30 sec
```

---

# 🔴 SECTION 8 — LATENCY BUDGET

```text id="lat1"
Ingest → Kafka: ≤ 50 ms
Kafka → Decision: ≤ 200 ms
Decision → Enforcement: ≤ 100 ms
Enforcement → Commit: ≤ 200 ms

TOTAL: ≤ 550 ms
```

---

# 🔴 SECTION 9 — REPLAY CLUSTER

```text id="rep1"
Dedicated replay cluster (isolated)
50 nodes
no shared resources with production
```

---
