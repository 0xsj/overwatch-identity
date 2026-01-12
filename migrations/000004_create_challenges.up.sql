-- Challenges table (ephemeral, for DID authentication)
CREATE TABLE IF NOT EXISTS challenges (
    id          TEXT PRIMARY KEY,
    did         TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT challenges_purpose_check CHECK (purpose IN ('register', 'authenticate'))
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_challenges_did ON challenges(did);
CREATE INDEX IF NOT EXISTS idx_challenges_expires_at ON challenges(expires_at);

-- Note: Challenges are typically stored in Redis with TTL.
-- This table is for fallback or when Redis is unavailable.
-- Consider running a periodic cleanup job for expired challenges.