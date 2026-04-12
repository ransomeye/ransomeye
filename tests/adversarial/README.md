# Adversarial Harness

Run the controlled ransomware-behavior validation harness with:

```bash
go run ./core/cmd/adversarial-harness
```

The harness validates:

- detection correctness
- enforcement latency
- false-negative / false-positive counts
- deterministic replay consistency

Checked-in sample output lives in `tests/adversarial/sample_output.json`.
