CREATE TABLE cloud_logs (
    log_id UUID PRIMARY KEY,

    event_time TIMESTAMPTZ NOT NULL,
    region_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    service_id TEXT NOT NULL,
    log_type TEXT NOT NULL,

    c BYTEA NOT NULL,
    t BYTEA NOT NULL,
    d BYTEA NOT NULL,

    UNIQUE(d)
);