CREATE TABLE auth_code_flows (
    code VARCHAR(32) PRIMARY KEY NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    flow_data JSON NOT NULL
);
