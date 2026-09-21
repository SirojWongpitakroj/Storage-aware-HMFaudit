# Audit service

The audit service exposes the two-stage verification read path. It never treats
addresses as authenticated until the auditor has verified the returned ALL
proof against the checkpoint's locator root.

Run it with:

```text
go run ./cmd/audit-service
```

Configuration is provided through environment variables:

```text
AUDIT_HTTP_ADDR=:8080
AUDIT_SYSTEM_ID=default
AUDIT_LOCATOR_TREE_ID=ALL
AUDIT_SHUTDOWN_TIMEOUT=10s
HPP_MAX_CONCURRENCY=8
CASSANDRA_HOSTS=127.0.0.1
CASSANDRA_PORT=9042
CASSANDRA_KEYSPACE=hmf_audit
CASSANDRA_DATACENTER=datacenter1
CASSANDRA_USERNAME=
CASSANDRA_PASSWORD=
```

## Endpoints

```text
GET  /healthz
GET  /readyz
GET  /v1/checkpoints/current
POST /v1/audits/locator-proof
POST /v1/audits/hmf-proof
```

Example locator request:

```json
{
  "tenant_id": "tenant-a",
  "service_id": "orders",
  "log_type": "audit",
  "region_id": "R0",
  "start_time": "2026-01-01T00:00:00Z",
  "end_time": "2026-01-02T00:00:00Z"
}
```

After verifying that response against `R_L`, the auditor submits the
authenticated addresses using the same checkpoint sequence:

```json
{
  "checkpoint_sequence": 4,
  "addresses": [
    {
      "region_id": "R0",
      "shard_id": 0,
      "segment_id": 12,
      "leaf_id": 30
    }
  ]
}
```

The HMF response contains the calculated `R_G'`, target Segment leaves, and
the deduplicated sibling nodes required to independently reconstruct `R_G`.
