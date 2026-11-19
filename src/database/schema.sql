CREATE TABLE IF NOT EXISTS analysis_runs (
    id SERIAL PRIMARY KEY,
    mode VARCHAR(10) NOT NULL,
    started_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS network_flows (
    id BIGSERIAL PRIMARY KEY,
    run_id INTEGER REFERENCES analysis_runs(id),
    src_ip INET,
    dst_ip INET,
    src_port INTEGER,
    dst_port INTEGER,
    protocol INTEGER,
    packet_count INTEGER,
    total_bytes BIGINT,
    duration DOUBLE PRECISION,
    anomaly_score DOUBLE PRECISION,
    status VARCHAR(20)
);

CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    flow_id BIGINT REFERENCES network_flows(id),
    detection_source VARCHAR(20),
    rule_alert TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
