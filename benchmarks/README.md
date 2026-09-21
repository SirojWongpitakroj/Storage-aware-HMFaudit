# Verification and tamper-localization latency benchmark

This benchmark measures the CPU/core latency of:

1. HMF multiproof verification against the trusted global root.
2. Tamper localization after changing one requested leaf.
3. Independent verification of the returned localization proof.

The standalone benchmark uses a deterministic synthetic HMF with 15-level,
`2^15`-leaf Segments and the maximum localization jump size `k = 63` (clamped
to each tree's height). Both clustered and scattered audit batches are
measured.

Verification proof construction occurs outside the verification timer.
Localization starts after a mismatch is known, but retains HMF-Audit's native
reference workflow inside the timer: reference-proof planning and in-memory
evidence retrieval, reference authentication, failed/reference tracing,
hierarchical pruning, and localization-evidence construction.

## Run

From the repository root:

```powershell
go run ./benchmarks/latency -iterations 200 -warmup 20 -sample-duration 20ms -batch-sizes 1,16,64,256,1024
python -m pip install -r benchmarks/requirements.txt
python benchmarks/plot_latency.py
```

Those values are also the defaults, so `go run ./benchmarks/latency` is enough.

Outputs:

```text
benchmarks/results/latency_raw.csv
benchmarks/results/latency_summary.csv
benchmarks/results/latency_percentiles.png
```

Each raw row is the average operation latency from a calibrated timing window,
which avoids zero-duration samples on coarse system clocks. The CSV records the
number of operations in each sample. The summary and graph show P50, P95, and
P99 sample latency by operation, placement, and batch size.

## Scope

These measurements intentionally exclude Cassandra, HTTP/JSON, blockchain, and
network latency. In-memory evidence reads remain inside native localization;
only the external transport is replaced by the benchmark fixture. Use a
separate end-to-end harness when measuring storage or network behavior.
