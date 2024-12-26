const schema = `
CREATE TABLE tokens (
    id UUID PRIMARY KEY,
    hash VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    family UUID NOT NULL,
    metadata JSONB NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    replaced_by VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_tokens_user_id ON tokens(user_id);
CREATE INDEX idx_tokens_family ON tokens(family);
CREATE INDEX idx_tokens_hash ON tokens(hash);
`
