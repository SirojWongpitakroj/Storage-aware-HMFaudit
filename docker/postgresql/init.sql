CREATE TABLE cloud_logs (
    log_id UUID PRIMARY KEY,

    event_time TIMESTAMPTZ NOT NULL,

    region_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    service_id TEXT NOT NULL,
    log_type TEXT NOT NULL,

    request_id TEXT,
    instance_id UUID,
    process_id INTEGER,
    logger TEXT,
    severity TEXT,

    raw_log TEXT NOT NULL,

    source_file TEXT NOT NULL,
    source_line BIGINT NOT NULL,

    dataset_class TEXT NOT NULL,

    UNIQUE (source_file, source_line)
);