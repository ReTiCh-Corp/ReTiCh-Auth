-- OAuth 2.0 client applications registered to use ReTiCh Auth as identity provider
CREATE TABLE oauth_clients (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id          TEXT UNIQUE NOT NULL,
    client_secret_hash TEXT NOT NULL,
    name               TEXT NOT NULL,
    logo_url           TEXT,
    redirect_uris      TEXT[] NOT NULL,
    allowed_scopes     TEXT[] NOT NULL DEFAULT '{openid,email,profile}',
    is_active          BOOLEAN DEFAULT TRUE,
    created_at         TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_oauth_clients_client_id ON oauth_clients(client_id);
