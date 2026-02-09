-- OAuth identities table: links external OAuth providers to users
CREATE TABLE IF NOT EXISTS oauth_identities (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider         TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    email            TEXT NOT NULL,
    name             TEXT,
    picture_url      TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_oauth_provider_user UNIQUE (provider, provider_user_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_identities_user_id ON oauth_identities (user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_identities_provider ON oauth_identities (provider);
CREATE INDEX IF NOT EXISTS idx_oauth_identities_email ON oauth_identities (email);

-- Auto-update updated_at on changes
CREATE OR REPLACE TRIGGER set_oauth_identities_updated_at
    BEFORE UPDATE ON oauth_identities
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

-- Add auth_method to sessions table to track how the session was created
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS auth_method TEXT NOT NULL DEFAULT 'did_challenge';
