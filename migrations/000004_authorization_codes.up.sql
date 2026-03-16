-- Authorization codes for OAuth 2.0 Authorization Code + PKCE flow
CREATE TABLE authorization_codes (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash      TEXT UNIQUE NOT NULL,
    client_id      TEXT NOT NULL,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    scopes         TEXT[] NOT NULL,
    code_challenge TEXT NOT NULL,
    nonce          TEXT,
    expires_at     TIMESTAMPTZ NOT NULL,
    used_at        TIMESTAMPTZ,
    created_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_auth_codes_code_hash  ON authorization_codes(code_hash);
CREATE INDEX idx_auth_codes_expires_at ON authorization_codes(expires_at) WHERE used_at IS NULL;
