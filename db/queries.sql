const schema = `
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash BYTEA NOT NULL,
    salt BYTEA NOT NULL,
    mfa_secret BYTEA,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    status VARCHAR(50) NOT NULL,
    failed_attempts INT DEFAULT 0,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tokens (
    id UUID PRIMARY KEY,
    hash VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id),
    family UUID NOT NULL,
    metadata JSONB NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    replaced_by UUID,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE security_events (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    metadata JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_tokens_user_id ON tokens(user_id);
CREATE INDEX idx_tokens_family ON tokens(family);
CREATE INDEX idx_tokens_hash ON tokens(hash);
CREATE INDEX idx_security_events_user_id ON security_events(user_id);
CREATE INDEX idx_security_events_type ON security_events(event_type);