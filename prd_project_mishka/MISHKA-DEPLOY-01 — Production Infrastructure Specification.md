# MISHKA-DEPLOY-01 — Production Infrastructure Specification

**Project:** Project Mishka  
**Classification:** DEPLOYMENT SPECIFICATION (NON-AUTHORITATIVE)

```text
THIS DOCUMENT IS NOT A PRD.

THIS DOCUMENT DEFINES DEPLOYMENT AND INFRASTRUCTURE PARAMETERS
DERIVED FROM AUTHORITATIVE PRDs.

AUTHORITY SOURCE:

- PRD-24 (Architecture)
- PRD-13 (Storage)
- PRD-08 (Ingest)
- PRD-01 (System Laws)

THIS DOCUMENT MUST NOT:

- introduce new system behavior
- override any PRD
- define new invariants

IF CONFLICT WITH ANY PRD:

→ THIS DOCUMENT IS INVALID
```

---

```text
SECTION: DERIVATION GUARANTEE (MANDATORY)

All values in this document MUST be:

- derived from PRDs
- deterministic functions of input assumptions

This document is:

NOT a source of truth
ONLY a projection of PRD-defined system behavior
```

---
```text
INPUT ASSUMPTIONS (MANDATORY):

agents = 1,000,000
avg_signals_per_agent_per_sec = 2
peak_burst_multiplier = 5
canonical_signal_size_bytes = 1024
```

Units:

* 1 KB = 1024 bytes (as specified)
* 1 GiB = 2^30 bytes
* 1 TiB = 2^40 bytes
* 1 PiB = 2^50 bytes

Alignment law (MANDATORY):

* Kafka is NON-authoritative transport only (PRD-24).
* PRD-13 committed storage is the ONLY authoritative state.
* Replay uses ONLY PRD-13 committed records (PRD-15).

---

## 1. THROUGHPUT MODEL (MANDATORY)

### 1.1 Total signals/sec

```text
total_signals_per_sec = agents * avg_signals_per_agent_per_sec
                     = 1,000,000 * 2
                     = 2,000,000 signals/sec
```

### 1.2 Peak signals/sec (5x burst)

```text
peak_signals_per_sec = total_signals_per_sec * peak_burst_multiplier
                     = 2,000,000 * 5
                     = 10,000,000 signals/sec
```

### 1.3 Ingress bandwidth (edge → ingest) for raw body bytes (PRD-16 → PRD-08)

```text
avg_ingress_bytes_per_sec  = 2,000,000 * 1024
                           = 2,048,000,000 bytes/sec
                           = 1.907 GiB/sec

peak_ingress_bytes_per_sec = 10,000,000 * 1024
                           = 10,240,000,000 bytes/sec
                           = 9.537 GiB/sec
```

In bits/sec:

```text
avg_ingress_gbps  = (2,048,000,000 * 8) / 1e9 = 16.384 Gbps
peak_ingress_gbps = (10,240,000,000 * 8) / 1e9 = 81.920 Gbps
```

### 1.4 Kafka write throughput (transport, NON-authoritative)

Kafka producer ingress (leader-append only, excluding replication fanout):

```text
avg_kafka_leader_ingress = 2,048,000,000 bytes/sec = 1.907 GiB/sec
peak_kafka_leader_ingress = 10,240,000,000 bytes/sec = 9.537 GiB/sec
```

Kafka replicated cluster write amplification for `replication_factor = 3`:

```text
avg_kafka_total_replica_write = avg_kafka_leader_ingress * 3
                             = 6,144,000,000 bytes/sec
                             = 5.722 GiB/sec

peak_kafka_total_replica_write = peak_kafka_leader_ingress * 3
                              = 30,720,000,000 bytes/sec
                              = 28.610 GiB/sec
```

### 1.5 Storage write throughput (PRD-13 authoritative commits)

PRD-13 stores canonical bytes plus mandatory metadata columns/hashes/signatures.

Authoritative committed size per `signal_record` (fixed sizing model):

```text
signal_record_bytes_committed = 1536 bytes
  = 1024 bytes canonical_payload_bytes
  + 512 bytes fixed commit metadata overhead
```

The 512-byte overhead covers (authoritative minimum, not optional):

* `message_id` (32)
* `payload_hash` (32)
* `canonical_payload_hash` (32)
* `partition_context` (16)
* `boot_session_id` (32)
* `logical_clock` (8)
* identity bytes / ids (>=16, fixed here as 32)
* signature Ed25519 (64)
* record hash chain fields (`previous_record_hash`, `record_hash`) (64)
* partition fields (partition_id/epoch/seq/shard ids) (fixed remainder)

Average authoritative storage ingest bytes/sec:

```text
avg_storage_bytes_per_sec = 2,000,000 * 1536
                          = 3,072,000,000 bytes/sec
                          = 2.861 GiB/sec

peak_storage_bytes_per_sec = 10,000,000 * 1536
                           = 15,360,000,000 bytes/sec
                           = 14.305 GiB/sec
```

---

## 2. KAFKA PARTITION CALCULATION (AUTHORITATIVE)

### 2.1 Safe bound: max msgs/sec per partition

Safe bound (MANDATORY):

```text
max_msgs_per_sec_per_partition = 5,000 msgs/sec
```

Justification (non-optional constraint):

* 5,000 msgs/sec * 1024 bytes/msg = 5,120,000 bytes/sec = 4.883 MiB/sec per partition leader append
* this bound preserves deterministic ordering, predictable consumer lag behavior, and stable disk segment flush without relying on best-effort jitter

### 2.2 Required partition count (peak)

```text
required_partitions_signal_ingest_log =
  ceil(peak_signals_per_sec / max_msgs_per_sec_per_partition)
= ceil(10,000,000 / 5,000)
= 2,000 partitions
```

### 2.3 Replication factor, ISR, and ACK

Kafka replication factor (MANDATORY):

```text
replication_factor = 3
min.insync.replicas = 2
acks = all
```

### 2.4 Broker count

Per-broker effective sustained replicated write capacity (MANDATORY sizing constant):

```text
broker_effective_replica_write_capacity = 1.0 GiB/sec
```

This constant is a deployment hardening guardrail:

* it is the maximum sustained **replicated** write budget per broker for PRD-24 transport logs under `acks=all`
* it is chosen to ensure headroom for:
  * ISR replication traffic
  * consumer read traffic
  * controller + metadata overhead
  * deterministic throttling under fault

Peak replicated write requirement (from Section 1.4):

```text
peak_kafka_total_replica_write = 28.610 GiB/sec
```

Required broker count:

```text
required_brokers = ceil(28.610 / 1.0) = 29
```

Production broker count (MANDATORY):

```text
brokers = 36
```

Failure tolerance (derived):

* with 36 brokers and RF=3, the cluster tolerates:
  * loss of 1 availability zone (rack-aware placement across 3 AZ) while preserving ISR>=2 for partitions whose replicas are AZ-distributed
  * loss of up to 12 brokers (one AZ) without losing correctness; throughput degrades deterministically by backpressure

---

## 3. TOPIC CONFIG (EXACT) (PRD-24 TOPICS)

Global Kafka defaults (MANDATORY):

```text
replication_factor_default = 3
min.insync.replicas = 2
acks = all
unclean.leader.election.enable = false
message.timestamp.type = CreateTime (non-authoritative metadata only)
```

Segment sizing (MANDATORY):

```text
segment.bytes = 1073741824  (1 GiB)
```

Retention law (MANDATORY):

* Kafka retention is for transport buffering only.
* Kafka retention MUST NOT be required for replay.

### 3.1 `signal_ingest_log`

```text
partitions = 2000
replication.factor = 3
cleanup.policy = delete
retention.ms = 86400000        (24h)
retention.bytes = 530000000000000  (530 TB)
segment.bytes = 1073741824     (1 GiB)
```

Retention.bytes calculation (explicit):

```text
avg_kafka_leader_ingress_per_day =
  2,048,000,000 bytes/sec * 86400
= 176,947,200,000,000 bytes/day

retention.bytes = 3 * avg_kafka_leader_ingress_per_day
               = 530,841,600,000,000 bytes
               = 530,000,000,000,000 bytes (rounded down to enforce bound)
```

### 3.2 `replay_guard_log` (COMPACTED)

NON-AUTHORITY NOTE (MANDATORY):
* `replay_guard_log` is a Kafka transport topic and is NON-authoritative (PRD-24).
* Kafka compaction state MUST NOT be treated as the durability anchor for replay-guard correctness.
* Replay-guard correctness MUST be enforced by committed PRD-13 `replay_guard` only.

Key cardinality:

```text
keys = (emitter_id, boot_session_id) ≈ active_sessions
active_sessions = 1,000,000
```

```text
partitions = 256
replication.factor = 3
cleanup.policy = compact
min.compaction.lag.ms = 0
max.compaction.lag.ms = 600000       (10m)
retention.ms = 2592000000            (30d)
retention.bytes = 200000000000       (200 GB)
segment.bytes = 1073741824           (1 GiB)
```

### 3.3 `decision_window_log`

```text
partitions = 1024
replication.factor = 3
cleanup.policy = delete
retention.ms = 21600000              (6h)
retention.bytes = 50000000000000     (50 TB)
segment.bytes = 1073741824           (1 GiB)
```

### 3.4 `feature_vector_log`

```text
partitions = 1024
replication.factor = 3
cleanup.policy = delete
retention.ms = 21600000              (6h)
retention.bytes = 20000000000000     (20 TB)
segment.bytes = 1073741824           (1 GiB)
```

### 3.5 `detection_event_log`

```text
partitions = 1024
replication.factor = 3
cleanup.policy = delete
retention.ms = 21600000              (6h)
retention.bytes = 20000000000000     (20 TB)
segment.bytes = 1073741824           (1 GiB)
```

### 3.6 `policy_decision_log`

```text
partitions = 1024
replication.factor = 3
cleanup.policy = delete
retention.ms = 21600000              (6h)
retention.bytes = 10000000000000     (10 TB)
segment.bytes = 1073741824           (1 GiB)
```

### 3.7 `action_execution_log`

```text
partitions = 1024
replication.factor = 3
cleanup.policy = delete
retention.ms = 86400000              (24h)
retention.bytes = 10000000000000     (10 TB)
segment.bytes = 1073741824           (1 GiB)
```

### 3.8 `execution_result_log`

```text
partitions = 1024
replication.factor = 3
cleanup.policy = delete
retention.ms = 86400000              (24h)
retention.bytes = 10000000000000     (10 TB)
segment.bytes = 1073741824           (1 GiB)
```

### 3.9 `worm_storage_log`

```text
partitions = 1024
replication.factor = 3
cleanup.policy = delete
retention.ms = 21600000              (6h)
retention.bytes = 50000000000000     (50 TB)
segment.bytes = 1073741824           (1 GiB)
```

### 3.10 `storage_commit_log`

```text
partitions = 256
replication.factor = 3
cleanup.policy = delete
retention.ms = 604800000             (7d)
retention.bytes = 1000000000000      (1 TB)
segment.bytes = 1073741824           (1 GiB)
```

---

## 4. SERVICE DEPLOYMENT (MANDATORY)

Hard constraints:

* services MUST NOT RPC-call each other for correctness (PRD-24)
* all correctness state MUST be derived from PRD-13 committed storage only
* Kafka is transport only; offsets are not authoritative

Sizing constants (MANDATORY):

```text
cpu_cores_per_instance = 32
memory_gib_per_instance = 128
network_gbps_per_instance = 25
```

These constants are applied uniformly for deterministic capacity planning.

### 4.1 Ingest Gateway

Work: PRD-16 transport termination + authN/authZ + framing + raw-byte handoff, then PRD-08 canonical validation + schema validation + signature/identity verification (batch) + durable admission + IO.

```text
instances = 200
cpu_per_instance = 32 cores
mem_per_instance = 128 GiB
consumer_group = N/A (producers)
partition_assignment = N/A
```

Capacity check:

```text
peak_signals_per_sec / instances = 10,000,000 / 200 = 50,000 signals/sec per instance
peak_ingress_bytes_per_sec / instances = 9.537 GiB/sec / 200 = 0.0477 GiB/sec = 48.9 MiB/sec per instance
```

### 4.2 Replay Guard

```text
instances = 256
cpu_per_instance = 32 cores
mem_per_instance = 128 GiB
consumer_group = replay-guard-cg
topic = signal_ingest_log
assignment = cooperative-sticky
```

Per-instance partition load:

```text
signal_ingest_log partitions / instances = 2000 / 256 = 7 partitions per instance (floor)
```

### 4.3 Partition Router

```text
instances = 128
cpu_per_instance = 32 cores
mem_per_instance = 128 GiB
consumer_group = partition-router-cg
topic = signal_ingest_log
assignment = cooperative-sticky
```

### 4.4 Decision Orchestrator

```text
instances = 1024
cpu_per_instance = 32 cores
mem_per_instance = 128 GiB
consumer_group = decision-orchestrator-cg
topic = decision_window_log
assignment = cooperative-sticky
```

### 4.5 Policy Engine

```text
instances = 512
cpu_per_instance = 32 cores
mem_per_instance = 128 GiB
consumer_group = policy-engine-cg
topic = detection_event_log
assignment = cooperative-sticky
```

### 4.6 Enforcement Engine

```text
instances = 512
cpu_per_instance = 32 cores
mem_per_instance = 128 GiB
consumer_group = enforcement-engine-cg
topic = policy_decision_log
assignment = cooperative-sticky
```

### 4.7 Storage Writer (CRITICAL)

PRD-13 requires partition-local single-writer semantics and bounded batching.

Define authoritative PRD-13 partition count for storage writers:

```text
storage_partitions = 2000
```

Deployment rule (MANDATORY):

```text
one active writer per storage partition leader epoch
```

Instances (MANDATORY):

```text
instances = 2000
cpu_per_instance = 16 cores
mem_per_instance = 64 GiB
consumer_group = storage-writer-cg
topic = worm_storage_log
assignment = static (1 partition-writer lane per instance)
```

### 4.8 Replay Engine (PRD-15)

Replay is storage-only and batch-oriented.

```text
instances = 64
cpu_per_instance = 32 cores
mem_per_instance = 256 GiB
input = PRD-13 storage only
```

---

## 5. STORAGE SIZING (PRD-13) (MANDATORY)

## 🔴 CAPACITY CONSISTENCY LAW (CRITICAL)

All storage sizing MUST satisfy:

```text
required_storage_bytes <= provisioned_storage_bytes
```

INCLUDING:

* HOT
* WARM
* COLD
* replication_factor
* at least 2 failure domains

IF violated:

```text
DEPLOYMENT CONFIG INVALID
→ FAIL-CLOSED
```

## 🔴 STORAGE DERIVATION RULE (MANDATORY)

`provisioned_storage` MUST be derived from:

```text
signal_rate
× record_size
× retention_window
× replication_factor
× failure_domain_factor
```

NO STATIC NUMBERS ALLOWED.

All storage sizing inputs MUST come from the signed deployment profile and active PRD-13 `config_snapshot_hash` scope.

### 5.1 Daily data volume (authoritative committed)

```text
signals_per_window = signal_rate * retention_window_seconds
signal_bytes_per_window = signals_per_window * signal_record_bytes
```

### 5.2 Commit metadata overhead

```text
batches_per_window = CEIL(signals_per_window / max_batch_record_count)
commit_bytes_per_window = batches_per_window * batch_commit_record_bytes
total_bytes_per_window = signal_bytes_per_window + commit_bytes_per_window
```

### 5.3 Required storage per tier

```text
required_hot_bytes =
  total_bytes_per_hot_window
  * replication_factor
  * failure_domain_factor

required_warm_bytes =
  total_bytes_per_warm_window
  * replication_factor
  * failure_domain_factor

required_cold_bytes =
  total_bytes_per_cold_window
  * replication_factor
  * failure_domain_factor
```

### 5.4 Provisioned storage derivation

```text
provisioned_storage_bytes =
  storage_node_count
  * usable_bytes_per_storage_node
```

Mandatory:

* `required_hot_bytes <= provisioned_hot_bytes`
* `required_warm_bytes <= provisioned_warm_bytes`
* `required_cold_bytes <= provisioned_cold_bytes`
* `required_storage_bytes <= provisioned_storage_bytes`

### 5.5 Required write throughput

Authoritative storage IO model (MANDATORY):

* partition writer uses append-only sequential writes
* fsync at each `batch_commit_record` boundary
* provisioned throughput MUST be derived from signed peak `signal_rate`, `signal_record_bytes`, and `batch_commit_record_bytes`

---

## 6. LATENCY BUDGET (MANDATORY)

These are operational SLOs; they MUST NOT be used as authoritative ordering inputs.

```text
max_ingest_to_kafka_ms = 50
max_kafka_to_decision_ms = 200
max_decision_to_enforcement_ms = 100
max_enforcement_to_commit_ms = 200

end_to_end_target_ms = 550
```

---

## 7. BACKPRESSURE THRESHOLDS (MANDATORY)

### 7.1 Kafka lag thresholds (record-count based, not time)

Define lag in records per partition (MANDATORY):

```text
kafka_lag_warn_records_per_partition = 100000
kafka_lag_backpressure_records_per_partition = 500000
kafka_lag_hard_stop_records_per_partition = 1000000
```

Enforcement (MANDATORY):

* WARN → emit pressure state THROTTLED upstream
* BACKPRESSURE → ingest returns `RESOURCE_EXHAUSTED` deterministically
* HARD_STOP → BLOCKED state and fail-closed for non-critical; CRITICAL follows PRD-05/08/13 reservation laws

### 7.2 Storage pressure %

Storage pressure thresholds are fixed by PRD-13 (hardening alignment):

```text
THROTTLE_THRESHOLD = 80%
BACKPRESSURE_THRESHOLD = 90%
HARD_STOP_THRESHOLD = 95%

EMERGENCY_RESERVE = 5%
```

### 7.3 Ingest rejection thresholds

Deterministic ingress rejection trigger (MANDATORY):

```text
if kafka_lag_records_per_partition >= kafka_lag_backpressure_records_per_partition:
    reject_with = RESOURCE_EXHAUSTED
```

### 7.4 Edge escrow limits

Edge MUST reserve bounded escrow capacity for CRITICAL signals (PRD-05).

Per-agent escrow capacity (MANDATORY sizing constant):

```text
edge_critical_escrow_bytes = 1073741824  (1 GiB)
```

Escrow exhaustion behavior (MANDATORY):

* if escrow exhausted → HALT (PRD-05 escrow law), not silent drop

---

## 8. FAILURE CAPACITY (MANDATORY)

### 8.1 Kafka broker failures tolerated

With `replication_factor = 3`, `min.insync.replicas = 2`, rack-aware across 3 AZ:

```text
max_az_failures_tolerated_for_availability = 1
```

On AZ loss:

* correctness preserved (Kafka non-authoritative)
* throughput degrades deterministically via backpressure

Recovery time targets (MANDATORY):

```text
kafka_recovery_rto_minutes = 30
```

### 8.2 Storage node failures tolerated

Authoritative storage MUST have >= 2 independent failure-domain replicas (PRD-13/15 multi-region replay backup).

```text
storage_failure_domains = 2
storage_node_failure_tolerance_per_domain = 1
```

Recovery time targets (MANDATORY):

```text
storage_partition_recovery_rto_minutes = 15
global_replay_failover_rto_minutes = 60
```

---

## 9. OUTPUT INTEGRITY NOTE (MANDATORY)

All computed values above are deterministic functions of the input assumptions and fixed sizing constants defined in this document.

If any implementation cannot satisfy these constraints without introducing:

* hidden state
* non-deterministic throttling
* Kafka-as-authority behavior

then:

```text
REJECT -> FAIL-CLOSED -> ALERT
```
