-- name: CreateSession :exec
INSERT INTO sessions (id, user_id, user_did, tenant_id, refresh_token_hash, expires_at, created_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: UpdateSession :exec
UPDATE sessions
SET refresh_token_hash = $2, expires_at = $3, revoked_at = $4
WHERE id = $1;

-- name: FindSessionByID :one
SELECT id, user_id, user_did, tenant_id, refresh_token_hash, expires_at, created_at, revoked_at
FROM sessions
WHERE id = $1;

-- name: FindSessionByRefreshTokenHash :one
SELECT id, user_id, user_did, tenant_id, refresh_token_hash, expires_at, created_at, revoked_at
FROM sessions
WHERE refresh_token_hash = $1;

-- name: FindActiveSessionsByUserID :many
SELECT id, user_id, user_did, tenant_id, refresh_token_hash, expires_at, created_at, revoked_at
FROM sessions
WHERE user_id = $1
  AND revoked_at IS NULL
  AND expires_at > NOW()
ORDER BY created_at DESC;

-- name: ListSessions :many
SELECT id, user_id, user_did, tenant_id, refresh_token_hash, expires_at, created_at, revoked_at
FROM sessions
WHERE (sqlc.narg('user_id')::text IS NULL OR user_id = sqlc.narg('user_id'))
  AND (sqlc.narg('tenant_id')::text IS NULL OR tenant_id = sqlc.narg('tenant_id'))
  AND (sqlc.arg('active_only')::bool = FALSE OR (revoked_at IS NULL AND expires_at > NOW()))
ORDER BY
    CASE WHEN sqlc.arg('sort_by') = 'created_at' AND sqlc.arg('sort_order') = 'asc' THEN created_at END ASC,
    CASE WHEN sqlc.arg('sort_by') = 'created_at' AND sqlc.arg('sort_order') = 'desc' THEN created_at END DESC,
    CASE WHEN sqlc.arg('sort_by') = 'expires_at' AND sqlc.arg('sort_order') = 'asc' THEN expires_at END ASC,
    CASE WHEN sqlc.arg('sort_by') = 'expires_at' AND sqlc.arg('sort_order') = 'desc' THEN expires_at END DESC,
    created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountSessions :one
SELECT COUNT(*)
FROM sessions
WHERE (sqlc.narg('user_id')::text IS NULL OR user_id = sqlc.narg('user_id'))
  AND (sqlc.narg('tenant_id')::text IS NULL OR tenant_id = sqlc.narg('tenant_id'))
  AND (sqlc.arg('active_only')::bool = FALSE OR (revoked_at IS NULL AND expires_at > NOW()));

-- name: RevokeSessionByID :exec
UPDATE sessions
SET revoked_at = NOW()
WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeAllSessionsByUserID :execrows
UPDATE sessions
SET revoked_at = NOW()
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions
WHERE expires_at < NOW() - INTERVAL '30 days';