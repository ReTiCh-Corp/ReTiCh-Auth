-- Persisted user consent per OAuth client (avoid re-prompting for same scopes)
CREATE TABLE oauth_consents (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    scopes     TEXT[] NOT NULL,
    granted_at TIMESTAMPTZ DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    UNIQUE(user_id, client_id)
);

CREATE INDEX idx_oauth_consents_user_client ON oauth_consents(user_id, client_id);
