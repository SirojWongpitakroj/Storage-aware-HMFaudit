-- CREATE TABLE cloud_logs (
--     log_id UUID PRIMARY KEY,

--     event_time TIMESTAMPTZ NOT NULL,
--     region_id TEXT NOT NULL,
--     tenant_id TEXT NOT NULL,
--     service_id TEXT NOT NULL,
--     log_type TEXT NOT NULL,

--     ciphertext BYTEA NOT NULL,
--     tag BYTEA NOT NULL,
--     nonce BYTEA NOT NULL,
--     digest BYTEA NOT NULL,

--     UNIQUE(d)
-- );

CREATE TABLE encrypted_logs (
    provider_id BIGSERIAL PRIMARY KEY,
    log_id UUID UNIQUE NOT NULL,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    associated_data BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);